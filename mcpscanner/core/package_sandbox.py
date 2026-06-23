# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Safe package-archive download & extraction for the no-Docker SDK path.

Docker remains the recommended sandbox for untrusted packages. When the SDK
caller explicitly opts out of Docker (``use_docker=False``) we still need to
download and extract a tarball on the host *without* giving the package a
chance to read/write outside the working directory or exhaust resources.

This module centralises that behaviour so PyPI and npm scanners share the
same defensive parsing path:

* HTTPS-only downloads to a temporary directory the caller owns.
* Streamed writes with an explicit byte cap (``PACKAGE_ARCHIVE_MAX_BYTES``).
* :mod:`tarfile` ``filter="data"`` extraction (Python 3.12+): drops symlinks,
  hardlinks, device files, absolute paths, and ``..`` traversal.
* Hard caps on total extracted bytes and file count to defend against
  zip-bombs.
* Digest verification with an allow-list of algorithms so a poisoned
  registry can't trick us into "verifying" against a broken hash.
* Archive bytes are streamed to a ``.partial`` sibling and only moved into
  place after integrity verification succeeds, so a tampered file never
  occupies its final filename even briefly.
* No code is *executed* from the package — we only read source files.

The local path is intentionally narrower than the Docker path: callers MUST
explicitly opt in by passing ``use_docker=False``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tarfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp
from typing import Iterable, Iterator, Optional, Sequence
from urllib.parse import ParseResult, urlparse

import httpx

from ..config.constants import MCPScannerConstants


# Names of environment variables we MUST never write to logs in plaintext.
# Pulled from the constants module's well-known LLM keys plus a defensive
# substring list so unknown providers added later still get redacted.
_SENSITIVE_ENV_NAMES = frozenset(
    {
        "LLM_API_KEY",
        "MCP_SCANNER_LLM_API_KEY",
        "MCP_SCANNER_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "VIRUSTOTAL_API_KEY",
    }
)
_SENSITIVE_ENV_SUBSTRINGS = ("_API_KEY", "_TOKEN", "_SECRET", "PASSWORD")


logger = logging.getLogger(__name__)


class PackageDownloadError(RuntimeError):
    """Raised when a package archive cannot be downloaded or is rejected."""


class PackageExtractionError(RuntimeError):
    """Raised when an archive fails the safe-extraction checks."""


class PackageIntegrityError(PackageDownloadError):
    """Raised when a downloaded archive doesn't match a published digest."""


# Digest algorithms we accept for integrity verification. ``sha1`` is weak
# but the npm registry still publishes the ``dist.shasum`` field as a SHA-1
# hex string for older packages; refusing it outright would force a
# regression. SHA-256/384/512 are the W3C-recommended SRI algorithms.
# Anything else (``md5``, ``md4``, custom names) is rejected to prevent a
# poisoned manifest from advertising a broken hash and getting us to
# "verify" against it.
_ALLOWED_DIGEST_ALGOS = frozenset({"sha1", "sha256", "sha384", "sha512"})


# ----------------------------------------------------------------------
# Log redaction (used by scanners that build docker run argv)
# ----------------------------------------------------------------------


def redact_argv_for_logging(argv: Sequence[str]) -> str:
    """Return a single string suitable for ``logger.debug`` that masks any
    ``KEY=VALUE`` pair whose key name looks like a credential.

    The two package scanners both build ``docker run -e LLM_API_KEY=<v>
    ...`` argvs and used to log them verbatim, which leaked LLM provider
    keys into DEBUG output. Routing both through this helper keeps the
    redaction in one place; adding a new sensitive env name above is the
    only step needed for future providers.
    """
    redacted: list[str] = []
    for piece in argv:
        if "=" in piece and not piece.startswith("-"):
            # ``-e KEY=VALUE`` is two argv entries (``-e``, ``KEY=VALUE``);
            # the value entry has the ``=`` so we redact here.
            key, _, value = piece.partition("=")
            if value and _is_sensitive_env_name(key):
                redacted.append(f"{key}=***REDACTED***")
                continue
        redacted.append(piece)
    return " ".join(redacted)


def _is_sensitive_env_name(name: str) -> bool:
    upper = name.upper()
    if upper in _SENSITIVE_ENV_NAMES:
        return True
    return any(sub in upper for sub in _SENSITIVE_ENV_SUBSTRINGS)


# ----------------------------------------------------------------------
# Temporary workdir helpers
# ----------------------------------------------------------------------


@contextmanager
def temp_workdir(prefix: str = "mcp-scanner-pkg-") -> Iterator[Path]:
    """Yield a private temp directory and unconditionally remove it on
    exit. ``shutil.rmtree`` is called with ``ignore_errors=True`` so a
    test process holding a file lock can't trip the cleanup."""
    workdir = Path(mkdtemp(prefix=prefix))
    try:
        yield workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ----------------------------------------------------------------------
# Download
# ----------------------------------------------------------------------


def download_archive(
    url: str,
    dest_dir: Path,
    *,
    filename: Optional[str] = None,
    max_bytes: Optional[int] = None,
    timeout: Optional[int] = None,
    expected_digest: Optional[str] = None,
    expected_digest_algo: Optional[str] = None,
    allowed_hosts: Optional[Sequence[str]] = None,
) -> Path:
    """Stream ``url`` to ``dest_dir`` with a hard byte cap.

    Args:
        url: HTTPS URL of the archive to download. ``http://`` is rejected
            because untrusted package fetches must use TLS, and the entire
            redirect chain is enforced to be HTTPS as well.
        dest_dir: Pre-existing directory the file will be written into.
        filename: Override the on-disk filename. Defaults to the URL
            path's basename (query string and fragment stripped).
        max_bytes: Per-archive size cap. Defaults to
            :pyattr:`MCPScannerConstants.PACKAGE_ARCHIVE_MAX_BYTES`.
        timeout: HTTP timeout in seconds. Defaults to
            :pyattr:`MCPScannerConstants.PACKAGE_DOWNLOAD_TIMEOUT`.
        expected_digest: Hex-encoded digest (or ``"<algo>-<b64>"`` SRI
            string as published by npm) the downloaded bytes must match.
            If supplied, mismatch raises :class:`PackageIntegrityError`.
        expected_digest_algo: Digest algorithm name (``sha256``,
            ``sha512``); required when ``expected_digest`` is a hex
            string. Ignored when ``expected_digest`` is already an
            SRI-formatted ``algo-base64`` string.
        allowed_hosts: Optional case-insensitive allow-list of hostnames
            the URL must resolve to. Defends against a compromised
            registry redirecting the tarball fetch to an attacker host.

    Returns:
        Path to the downloaded file.

    Raises:
        PackageDownloadError: On HTTP failure, scheme mismatch, size
            limit breach, or unexpected host.
        PackageIntegrityError: When ``expected_digest`` is provided and
            the on-disk bytes don't match.
    """
    # Final URL after redirect resolution; updated on each 3xx hop so the
    # on-disk filename and the digest-verified bytes both correspond to the
    # CDN endpoint we ultimately read from rather than the first URL we
    # tried. Seeded with the validator's ParseResult so we don't pay for a
    # second ``urlparse`` of the same string.
    final_parsed = _validate_https_url(url, allowed_hosts)

    cap = max_bytes if max_bytes is not None else MCPScannerConstants.PACKAGE_ARCHIVE_MAX_BYTES
    http_timeout = (
        timeout if timeout is not None else MCPScannerConstants.PACKAGE_DOWNLOAD_TIMEOUT
    )

    digest_algo, digest_expected_hex = _normalise_expected_digest(
        expected_digest, expected_digest_algo
    )
    try:
        hasher = hashlib.new(digest_algo) if digest_algo else None
    except (ValueError, TypeError) as e:
        # Defense in depth: ``_normalise_expected_digest`` already filtered
        # algos against an allow-list, but hashlib backends differ between
        # Python builds so wrap unsupported-algo crashes as our typed error.
        raise PackageDownloadError(
            f"hash algorithm {digest_algo!r} unsupported by this Python: {e}"
        ) from e

    target: Optional[Path] = None
    target_partial: Optional[Path] = None
    written = 0
    try:
        with httpx.Client(
            timeout=http_timeout,
            # Disable transparent redirect-following so we can verify
            # every hop's scheme + host ourselves. The same client is
            # reused so connection pooling still works.
            follow_redirects=False,
            headers={"User-Agent": "mcp-scanner/package-sandbox"},
        ) as client:
            stream_url = url
            for _hop in range(_MAX_REDIRECT_HOPS):
                with client.stream("GET", stream_url) as resp:
                    if resp.is_redirect:
                        stream_url, final_parsed = _next_redirect_target(
                            stream_url, resp, allowed_hosts
                        )
                        continue

                    resp.raise_for_status()
                    content_length = resp.headers.get("content-length")
                    if content_length is not None:
                        try:
                            if int(content_length) > cap:
                                raise PackageDownloadError(
                                    f"archive Content-Length {content_length} exceeds "
                                    f"cap {cap} bytes"
                                )
                        except ValueError:
                            # Non-numeric header — ignore and rely on stream cap.
                            pass

                    # Resolve the target filename once we know which URL
                    # the response is actually coming from. Streaming to a
                    # ``.partial`` sibling means a tampered file never
                    # appears at its final name, even briefly.
                    target_name = filename or _safe_filename_from_url(
                        final_parsed.path
                    )
                    if (
                        not target_name
                        or "/" in target_name
                        or "\\" in target_name
                        or target_name in (".", "..")
                    ):
                        raise PackageDownloadError(
                            "refusing suspicious archive filename derived from URL: "
                            f"{target_name!r}"
                        )
                    target = dest_dir / target_name
                    target_partial = target.with_name(target.name + ".partial")

                    with open(target_partial, "wb") as fh:
                        for chunk in resp.iter_bytes(chunk_size=64 * 1024):
                            # Check the cap BEFORE the write so a hostile
                            # server slow-trickling bytes can't fill the
                            # tempdir one chunk at a time.
                            if written + len(chunk) > cap:
                                raise PackageDownloadError(
                                    f"archive exceeded {cap} bytes during download"
                                )
                            fh.write(chunk)
                            written += len(chunk)
                            if hasher is not None:
                                hasher.update(chunk)
                    break
            else:
                raise PackageDownloadError(
                    f"too many redirects ({_MAX_REDIRECT_HOPS}) while fetching {url!r}"
                )
    except PackageDownloadError:
        if target_partial is not None:
            target_partial.unlink(missing_ok=True)
        raise
    except httpx.HTTPError as e:
        if target_partial is not None:
            target_partial.unlink(missing_ok=True)
        raise PackageDownloadError(f"HTTP error downloading {url}: {e}") from e

    # Defensive runtime check (instead of ``assert``, which ``python -O``
    # would strip): the only way to reach this point is via the ``break``
    # after the partial file was written, but if the control flow ever
    # changes we want a typed error rather than ``os.replace(None, None)``.
    if target is None or target_partial is None:
        raise PackageDownloadError(
            f"internal error: download_archive completed without "
            f"establishing a target file for {url!r}"
        )

    if hasher is not None and digest_expected_hex is not None:
        actual = hasher.hexdigest()
        if not _digests_equal(actual, digest_expected_hex):
            target_partial.unlink(missing_ok=True)
            raise PackageIntegrityError(
                f"{digest_algo} digest mismatch for {url!r}: "
                f"expected {digest_expected_hex}, got {actual}"
            )

    # Only now publish the verified bytes at the final name. ``os.replace``
    # is atomic on POSIX and on Windows when source and target are on the
    # same filesystem (always true here: same dest_dir).
    os.replace(target_partial, target)

    logger.debug(
        "package_sandbox downloaded url=%s final_url=%s bytes=%d path=%s integrity=%s",
        url,
        _format_final_url(final_parsed),
        written,
        target,
        "verified" if hasher is not None else "skipped",
    )
    return target


_MAX_REDIRECT_HOPS = 10


def _validate_https_url(url: str, allowed_hosts: Optional[Sequence[str]]) -> ParseResult:
    """Parse ``url`` and reject anything that isn't HTTPS or that points
    at a host outside ``allowed_hosts`` (when supplied)."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise PackageDownloadError(
            f"refusing non-HTTPS URL during package fetch: {url!r}"
        )
    if not parsed.netloc:
        raise PackageDownloadError(f"refusing URL with no host: {url!r}")
    if allowed_hosts:
        host = parsed.hostname or ""
        host_lower = host.lower()
        if not any(
            host_lower == allowed.lower()
            or host_lower.endswith("." + allowed.lower().lstrip("."))
            for allowed in allowed_hosts
        ):
            raise PackageDownloadError(
                f"refusing URL host {host!r}; not in allow-list {list(allowed_hosts)!r}"
            )
    return parsed


def _safe_filename_from_url(url_path: str) -> str:
    """Pull the basename out of a URL path, stripping query/fragment.
    ``urlparse`` already drops those for us, so this is just the trailing
    path segment."""
    name = url_path.rsplit("/", 1)[-1]
    return name


def classify_exception(exc: BaseException) -> str:
    """Map an exception raised inside a scan to the stable ``error_code``
    vocabulary documented in ``docs/pypi-scanning.md`` and
    ``docs/npm-scanning.md``.

    Both Docker entrypoints and any future caller that wants to surface
    structured errors should use this rather than maintain their own
    string-matching table — the documented vocabulary is what host code
    branches on, so it must stay single-sourced. ``isinstance`` is used
    instead of class-name matching to avoid silent collisions if two
    unrelated ``LLMNotConfiguredError`` classes ever coexist (e.g. during
    a rename).

    Returned codes:

    * ``llm_not_configured`` — caller is missing the LLM API key the SDK
      needs to run (local mode only).
    * ``package_download_failed`` — any download-time problem, including
      integrity (digest) mismatches.
    * ``package_extraction_failed`` — archive landed but couldn't be
      unpacked safely.
    * ``scan_failed`` — fallback for unclassified exceptions, including
      the rare case where importing the typed exception classes itself
      fails (logged at WARNING so the operator can investigate).
    """
    try:
        from .pypi_scanner import LLMNotConfiguredError
    except Exception as import_err:  # noqa: BLE001 - defensive
        # An ImportError here is unusual — it implies the install is
        # corrupted or a circular import was just introduced. Log it
        # loudly so operators don't get a stream of opaque
        # ``scan_failed`` codes without knowing why.
        logger.warning(
            "classify_exception fell back to scan_failed because the "
            "typed exception classes could not be imported: %s",
            import_err,
        )
        return "scan_failed"

    if isinstance(exc, LLMNotConfiguredError):
        return "llm_not_configured"
    if isinstance(exc, (PackageDownloadError, PackageIntegrityError)):
        return "package_download_failed"
    if isinstance(exc, PackageExtractionError):
        return "package_extraction_failed"
    return "scan_failed"


def _format_final_url(parsed: ParseResult) -> str:
    """Render a ``ParseResult`` for safe logging. Uses ``hostname`` (and
    ``port`` if present) rather than the raw ``netloc`` so any
    ``user:pass@`` userinfo on the source URL is stripped before
    hitting DEBUG output. Defense in depth — neither PyPI nor npm
    advertise userinfo in URLs, but operators with private mirrors
    sometimes do."""
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port}{parsed.path}"


def _next_redirect_target(
    current_url: str,
    response: httpx.Response,
    allowed_hosts: Optional[Sequence[str]],
) -> tuple[str, ParseResult]:
    """Resolve and validate the ``Location`` header on a 3xx response.

    Both :func:`download_archive` (streaming) and :func:`_https_get_json`
    (eager) need the exact same redirect-target logic — extract the
    header, join against the current URL, and enforce HTTPS + the host
    allow-list at every hop. Factoring it out keeps the policy in one
    place so a future addition (e.g. blocking redirects across registry
    domains) only needs to be made once.

    Returns:
        ``(next_url, parsed_next)`` ready for the next request.

    Raises:
        PackageDownloadError: If the header is missing, the scheme
            downgrades, or the host falls outside ``allowed_hosts``.
    """
    next_url = response.headers.get("location")
    if not next_url:
        raise PackageDownloadError(
            f"redirect at {current_url!r} without a Location header"
        )
    resolved = str(response.url.join(next_url))
    # Emit a redirect-specific error before delegating to the generic
    # validator. ``_validate_https_url`` raises an accurate but generic
    # "non-HTTPS URL during package fetch" message; operators
    # debugging a downgrade attack want to see the redirect framing so
    # they look at the CDN logs first, not the initial URL builder.
    parsed_pre = urlparse(resolved)
    if parsed_pre.scheme.lower() != "https":
        raise PackageDownloadError(
            f"refusing HTTP redirect from {current_url!r} to {resolved!r}"
        )
    parsed = _validate_https_url(resolved, allowed_hosts)
    return resolved, parsed


def _normalise_expected_digest(
    expected: Optional[str], algo: Optional[str]
) -> tuple[Optional[str], Optional[str]]:
    """Accept either a hex digest + algo name, or an SRI-style
    ``algo-base64`` string (the npm registry uses the latter). Return
    ``(algo, hex_digest)`` so the streaming loop only has to deal with
    one shape.

    The algorithm — whether explicit or pulled out of the SRI prefix —
    must be in :data:`_ALLOWED_DIGEST_ALGOS`. Refusing arbitrary algos
    means a poisoned manifest cannot publish ``"md5-..."`` and get us to
    "verify" the download against a hash whose collision cost is
    feasible.
    """
    if expected is None:
        return (None, None)
    if "-" in expected and not _looks_like_hex(expected):
        algo_name, _, b64_part = expected.partition("-")
        algo_lower = algo_name.lower()
        if algo_lower not in _ALLOWED_DIGEST_ALGOS:
            raise PackageDownloadError(
                f"refusing unsupported digest algorithm {algo_lower!r} in "
                f"SRI integrity string {expected!r}; allowed: "
                f"{sorted(_ALLOWED_DIGEST_ALGOS)}"
            )
        try:
            import base64

            raw = base64.b64decode(b64_part, validate=True)
        except Exception as e:
            raise PackageDownloadError(
                f"unparseable SRI integrity string {expected!r}: {e}"
            ) from e
        return (algo_lower, raw.hex())
    if not algo:
        raise PackageDownloadError(
            "expected_digest is a raw hex string but expected_digest_algo "
            "was not supplied"
        )
    algo_lower = algo.lower()
    if algo_lower not in _ALLOWED_DIGEST_ALGOS:
        raise PackageDownloadError(
            f"refusing unsupported digest algorithm {algo_lower!r}; "
            f"allowed: {sorted(_ALLOWED_DIGEST_ALGOS)}"
        )
    if not _looks_like_hex(expected):
        raise PackageDownloadError(
            f"expected_digest {expected!r} doesn't look like a hex digest"
        )
    return (algo_lower, expected.lower())


def _looks_like_hex(value: str) -> bool:
    if not value:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def _digests_equal(actual_hex: str, expected_hex: str) -> bool:
    # Use compare_digest to avoid the (admittedly tiny) timing-oracle risk
    # if expected_hex ever comes from user-controlled input.
    import hmac

    return hmac.compare_digest(actual_hex.lower(), expected_hex.lower())


# ----------------------------------------------------------------------
# Extract
# ----------------------------------------------------------------------


def safe_extract_tar_gz(
    archive: Path,
    dest_dir: Path,
    *,
    max_extracted_bytes: Optional[int] = None,
    max_files: Optional[int] = None,
    only_dirs: bool = False,
) -> Path:
    """Extract a gzipped tarball under ``dest_dir`` using the tarfile
    ``data`` filter, with hard caps on total bytes and file count.

    The ``data`` filter (Python 3.12+) drops:

    * Members with absolute paths or ``..`` traversal.
    * Symlinks and hardlinks pointing outside the extraction root.
    * Device, FIFO, and other special files.
    * Members with permissions that include setuid/setgid.

    Combined with the byte/file caps this protects against zip bombs and
    path traversal even when the caller has opted out of Docker isolation.

    Args:
        archive: Path to a ``.tgz`` / ``.tar.gz`` file.
        dest_dir: Pre-existing empty directory to extract into.
        max_extracted_bytes: Total extracted-size cap. Defaults to
            :pyattr:`MCPScannerConstants.PACKAGE_EXTRACTED_MAX_BYTES`.
        max_files: Cap on the number of entries extracted. Defaults to
            :pyattr:`MCPScannerConstants.PACKAGE_EXTRACTED_MAX_FILES`.
        only_dirs: Forwarded to :func:`_resolve_single_root`; see there
            for the PyPI-specific "ignore root-level sibling files when
            deciding the package root" semantics.

    Returns:
        The path to ``dest_dir`` (for chaining) or a single
        package-named subdirectory if the archive contained only one.

    Raises:
        PackageExtractionError: On cap breach or member rejection.
    """
    bytes_cap = (
        max_extracted_bytes
        if max_extracted_bytes is not None
        else MCPScannerConstants.PACKAGE_EXTRACTED_MAX_BYTES
    )
    files_cap = (
        max_files
        if max_files is not None
        else MCPScannerConstants.PACKAGE_EXTRACTED_MAX_FILES
    )

    try:
        with tarfile.open(archive, "r:gz") as tf:
            members = tf.getmembers()
            if len(members) > files_cap:
                raise PackageExtractionError(
                    f"archive contains {len(members)} members, exceeds cap {files_cap}"
                )

            total_size = 0
            for m in members:
                # tarfile reports the in-archive declared size; this lets us
                # reject zip-bombs *before* we write a single byte.
                if m.size and m.size > bytes_cap:
                    raise PackageExtractionError(
                        f"member {m.name!r} declared size {m.size} exceeds cap {bytes_cap}"
                    )
                total_size += m.size
                if total_size > bytes_cap:
                    raise PackageExtractionError(
                        f"total declared size {total_size} exceeds cap {bytes_cap}"
                    )

            # ``filter="data"`` raises on absolute/traversal/symlink members.
            tf.extractall(dest_dir, filter="data")
    except PackageExtractionError:
        raise
    except (tarfile.TarError, OSError) as e:
        raise PackageExtractionError(f"tarball extraction failed: {e}") from e

    return _resolve_single_root(dest_dir, only_dirs=only_dirs)


def safe_extract_zip(
    archive: Path,
    dest_dir: Path,
    *,
    max_extracted_bytes: Optional[int] = None,
    max_files: Optional[int] = None,
    only_dirs: bool = False,
) -> Path:
    """Extract a ``.zip``/``.whl`` source distribution under ``dest_dir``
    with the same defensive checks ``safe_extract_tar_gz`` applies to
    tarballs.

    Zip has no equivalent of tarfile's ``data`` filter, so we validate
    each member ourselves:

    * Names with absolute paths or ``..`` traversal are rejected.
    * Backslashes in member names are rejected (Windows path tricks).
    * Per-member uncompressed size is bounded; the cumulative total is
      also bounded.
    * The member count is capped.

    Raises:
        PackageExtractionError: On cap breach or unsafe member name.
    """
    bytes_cap = (
        max_extracted_bytes
        if max_extracted_bytes is not None
        else MCPScannerConstants.PACKAGE_EXTRACTED_MAX_BYTES
    )
    files_cap = (
        max_files
        if max_files is not None
        else MCPScannerConstants.PACKAGE_EXTRACTED_MAX_FILES
    )

    try:
        with zipfile.ZipFile(archive, "r") as zf:
            infos = zf.infolist()
            if len(infos) > files_cap:
                raise PackageExtractionError(
                    f"zip contains {len(infos)} entries, exceeds cap {files_cap}"
                )

            total = 0
            for info in infos:
                # ``filename`` is the raw stored path; defend against
                # absolute paths, traversal, and Windows ``\`` separators.
                if (
                    not info.filename
                    or info.filename.startswith(("/", "\\"))
                    or "\\" in info.filename
                    or ".." in Path(info.filename).parts
                ):
                    raise PackageExtractionError(
                        f"unsafe zip member name: {info.filename!r}"
                    )
                if info.file_size > bytes_cap:
                    raise PackageExtractionError(
                        f"member {info.filename!r} declared size "
                        f"{info.file_size} exceeds cap {bytes_cap}"
                    )
                total += info.file_size
                if total > bytes_cap:
                    raise PackageExtractionError(
                        f"total declared zip size {total} exceeds cap {bytes_cap}"
                    )

            # zipfile.extract() resolves through any leading ``..`` by
            # itself; the per-member checks above already reject the
            # obvious tricks but we re-check the resolved on-disk path
            # against ``dest_dir`` as a defense-in-depth belt for older
            # Python builds where ``extract`` may not normalise as
            # aggressively.
            dest_resolved = dest_dir.resolve()
            for info in infos:
                out_path = Path(zf.extract(info, dest_dir)).resolve()
                try:
                    out_path.relative_to(dest_resolved)
                except ValueError:
                    raise PackageExtractionError(
                        f"zip member {info.filename!r} resolved to "
                        f"{out_path!s}, outside extraction root "
                        f"{dest_resolved!s}"
                    )
    except PackageExtractionError:
        raise
    except (zipfile.BadZipFile, OSError) as e:
        raise PackageExtractionError(f"zip extraction failed: {e}") from e

    return _resolve_single_root(dest_dir, only_dirs=only_dirs)


# Suffix → extractor dispatch. Both keys lower-case; callers should pass
# ``archive.name.lower()`` (or use :func:`safe_extract_archive` directly).
_TAR_GZ_SUFFIXES = (".tar.gz", ".tgz")
_ZIP_SUFFIXES = (".zip", ".whl")


def safe_extract_archive(
    archive: Path,
    dest_dir: Path,
    *,
    max_extracted_bytes: Optional[int] = None,
    max_files: Optional[int] = None,
    only_dirs: bool = False,
) -> Path:
    """Dispatch to :func:`safe_extract_tar_gz` or :func:`safe_extract_zip`
    based on the archive's filename. Defaults / caps are forwarded as-is.

    PyPI sdists are usually ``.tar.gz`` but the index also serves ``.zip``
    for some packages; the local pypi scanner must accept both to avoid a
    silent regression vs the Docker entrypoint.

    ``only_dirs`` is forwarded to the chosen extractor and ultimately to
    :func:`_resolve_single_root`. See that function for the rationale —
    short version: the PyPI Docker path opts in to preserve historical
    "single-dir even if pip dropped sibling READMEs" semantics.
    """
    name = archive.name.lower()
    if name.endswith(_TAR_GZ_SUFFIXES):
        return safe_extract_tar_gz(
            archive,
            dest_dir,
            max_extracted_bytes=max_extracted_bytes,
            max_files=max_files,
            only_dirs=only_dirs,
        )
    if name.endswith(_ZIP_SUFFIXES):
        return safe_extract_zip(
            archive,
            dest_dir,
            max_extracted_bytes=max_extracted_bytes,
            max_files=max_files,
            only_dirs=only_dirs,
        )
    raise PackageExtractionError(
        f"unsupported archive format: {archive.name!r} (expected tar.gz/tgz/zip/whl)"
    )


# Synthetic tar member names that some publishers leave behind alongside
# the real package root. They confuse the "single subdir?" heuristic in
# :func:`_resolve_single_root` because they look like extra siblings.
# ``__MACOSX`` is the resource-fork directory ``tar`` produces on macOS;
# ``pax_*`` / ``@PaxHeader`` are POSIX.1-2001 metadata records; ``@LongLink``
# / ``@LongName`` are GNU tar extensions for paths > 100 bytes.
_PSEUDO_TAR_ENTRIES = frozenset(
    {
        "pax_global_header",
        ".pax_global_header",
        "pax_header",
        "@PaxHeader",
        "@LongLink",
        "@LongName",
        "__MACOSX",
    }
)


def _resolve_single_root(dest_dir: Path, *, only_dirs: bool = False) -> Path:
    """If the archive extracted to a single subdirectory (common for npm
    tarballs which always have a ``package/`` root, and for PyPI sdists
    which have ``<name>-<version>/``), return that subdirectory so callers
    don't need to glob. Otherwise return ``dest_dir`` as-is.

    Args:
        dest_dir: The extraction destination.
        only_dirs: When True, only directories are counted toward the
            "is there exactly one root child?" decision; root-level
            sibling files (``README``, ``LICENSE``) are ignored. The
            PyPI Docker entrypoint enables this to preserve its
            historical "select the single ``<name>-<version>/`` subdir
            even if pip dropped sibling files alongside it" behaviour.
            Default False keeps the npm path strict — npm tarballs
            should never have sibling files at root.
    """
    if only_dirs:
        children = [
            p
            for p in dest_dir.iterdir()
            if p.is_dir()
            and not p.name.startswith(".")
            and p.name not in _PSEUDO_TAR_ENTRIES
        ]
        if len(children) == 1:
            return children[0]
        return dest_dir

    children = [
        p
        for p in dest_dir.iterdir()
        if not p.name.startswith(".") and p.name not in _PSEUDO_TAR_ENTRIES
    ]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest_dir


# ----------------------------------------------------------------------
# Source-file counting (shared between Docker entrypoints and SDK)
# ----------------------------------------------------------------------


def count_source_files(
    source_root: Path,
    *,
    extensions: Iterable[str],
    skip_dirs: Iterable[str] = (),
    skip_hidden: bool = True,
) -> int:
    """Count files under ``source_root`` whose suffix is in ``extensions``
    and that don't live under one of ``skip_dirs`` (or any hidden dir
    when ``skip_hidden`` is True).

    Used by every scanner-result emitter — Docker entrypoints and SDK
    callers — so the ``*_files_scanned`` field carries the same value
    regardless of execution mode. Diverging this between modes used to
    silently inflate or deflate the count depending on whether the
    package shipped a ``dist/`` directory.
    """
    ext_lower = {e.lower() for e in extensions}
    skip_set = {d for d in skip_dirs}
    count = 0
    for path in source_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in ext_lower:
            continue
        parts = path.parts
        if any(part in skip_set for part in parts):
            continue
        if skip_hidden and any(part.startswith(".") for part in parts):
            continue
        count += 1
    return count
