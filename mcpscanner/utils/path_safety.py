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
"""Path-safety helpers used by directory-walking analyzers.

The behavioural code analyzer and the VirusTotal analyzer both walk a
user-supplied directory with ``Path.rglob`` and then read or hash each
matching file. By default ``Path.rglob`` matches symlinked files, and
``open()`` / ``Path.read_bytes()`` follow those links — so a hostile or
careless directory layout that contains a symlink to a file outside the
scan root would cause that external file to be ingested by the scanner
(and, with the VT analyzer's upload mode, exfiltrated to VirusTotal).

This module centralises the defence: resolve the scan root once, resolve
each candidate, and reject anything whose canonical location escapes the
root. Callers also get a single place to log the decision so audit trails
are consistent across analyzers.

The behaviour intentionally rejects symlinks whose target lies outside
the scan root rather than rejecting all symlinks — symlinks that stay
inside the project (e.g. ``node_modules/.bin``) are legitimate and would
otherwise produce false negatives for legitimate scans.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path, PurePosixPath
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

_MAX_CONFINED_PATH_LEN = 4096
_SAFE_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ConfinedPathNotFoundError(ValueError):
    """Raised when a validated confined path does not exist on disk."""


def safe_resolve_root(directory: str | os.PathLike) -> Path:
    """Resolve ``directory`` to an absolute, symlink-free canonical path.

    The result is what every per-file ``is_within_root`` check is measured
    against. ``strict=False`` lets us accept paths whose terminal component
    does not yet exist (some test fixtures rely on that), but the rest of
    the chain is still resolved.
    """
    return Path(directory).resolve(strict=False)


def is_within_root(candidate: Path, resolved_root: Path) -> bool:
    """Return ``True`` iff ``candidate`` resolves to a location inside
    ``resolved_root``.

    The check uses :py:meth:`Path.resolve` on the candidate so the answer
    reflects the *target* of any intervening symlinks, not the symlink
    name. ``resolved_root`` is expected to already be the output of
    :func:`safe_resolve_root` — we do not re-resolve it on every call to
    keep the per-file cost down on large trees.
    """
    try:
        resolved_candidate = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        # ``resolve()`` can raise on broken symlinks or on cycles; treat
        # both as "not safe to read" rather than propagating.
        return False

    if resolved_candidate == resolved_root:
        return True
    try:
        resolved_candidate.relative_to(resolved_root)
        return True
    except ValueError:
        return False


def filter_safe_paths(
    candidates,
    resolved_root: Path,
    *,
    audit_label: str = "scan",
) -> Tuple[list, int]:
    """Filter an iterable of ``Path`` candidates down to ones that stay
    inside ``resolved_root``.

    Returns ``(safe_paths, skipped_count)``. Each rejected candidate is
    logged at ``WARNING`` so an operator can see — after the fact — that
    a symlink escape was attempted on the directory they handed to the
    scanner. We deliberately do not log the symlink *target* at WARNING
    level: that target is the very file the attacker tried to exfiltrate,
    and echoing it into shared logs would defeat the defence. The target
    is only emitted at DEBUG, where local operators can opt in.
    """
    safe: list = []
    skipped = 0
    for candidate in candidates:
        if is_within_root(candidate, resolved_root):
            safe.append(candidate)
            continue

        skipped += 1
        try:
            target_repr: Optional[str] = str(candidate.resolve(strict=False))
        except Exception:
            target_repr = None

        logger.warning(
            "[%s] skipping symlink that escapes scan root: %s",
            audit_label,
            candidate,
        )
        if target_repr is not None:
            logger.debug(
                "[%s] escape target was: %s (root=%s)",
                audit_label,
                target_repr,
                resolved_root,
            )
    return safe, skipped


def validate_confined_path_input(source_path: str) -> tuple[str, ...]:
    """Validate API-supplied path text before any filesystem operations.

    Returns the normalized relative path components. Rejects traversal,
    home expansion, absolute paths, and other values that must not reach
    :class:`pathlib.Path` construction directly from request input.
    """
    if not isinstance(source_path, str):
        raise ValueError("source_path must be a string")
    if not source_path or source_path.isspace():
        raise ValueError("source_path must be a non-empty string")
    if len(source_path) > _MAX_CONFINED_PATH_LEN:
        raise ValueError("source_path exceeds maximum allowed length")
    if "\x00" in source_path:
        raise ValueError("source_path contains null bytes")
    if source_path.startswith("~"):
        raise ValueError("source_path must not use home-directory expansion")

    pure = PurePosixPath(source_path.replace("\\", "/"))
    if pure.is_absolute():
        raise ValueError("source_path must be relative to the configured API root")
    if ".." in pure.parts:
        raise ValueError("source_path must not contain '..' segments")

    parts: list[str] = []
    for part in pure.parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError("source_path must not contain '..' segments")
        if not _SAFE_PATH_SEGMENT_RE.fullmatch(part):
            raise ValueError(
                "source_path contains invalid characters; "
                "use alphanumeric names with . _ - only"
            )
        parts.append(part)

    if not parts:
        raise ValueError("source_path must not be empty")
    return tuple(parts)


def _canonical_root(resolved_root: str | os.PathLike) -> str:
    """Return a symlink-resolved absolute root directory path."""
    try:
        return os.path.realpath(os.fspath(resolved_root))
    except OSError as exc:
        raise ValueError(
            f"Root {resolved_root!r} could not be resolved safely"
        ) from exc


def _confined_path_string(root: str, parts: tuple[str, ...]) -> str:
    """Build a confined absolute path string under ``root`` using ``os.path``."""
    fullpath = os.path.normpath(os.path.join(root, *parts))
    if fullpath != root and not fullpath.startswith(root + os.sep):
        raise ValueError(f"Path {parts!r} is outside the allowed root {root!r}")
    return fullpath


def sanitize_confined_path(
    source_path: str | os.PathLike,
    resolved_root: str | os.PathLike,
    *,
    must_exist: bool = False,
) -> str:
    """Validate and return a confined absolute path string safe for file access.

    Uses ``os.path.normpath`` / ``os.path.realpath`` with a root prefix check so
    static analysis can treat the returned value as sanitized. When
    ``must_exist`` is true, the existence probe runs only after that guard.
    """
    parts = validate_confined_path_input(os.fspath(source_path))
    root = _canonical_root(resolved_root)
    fullpath = _confined_path_string(root, parts)
    if must_exist and not os.path.lexists(fullpath):
        raise ConfinedPathNotFoundError(
            f"Path {source_path!r} does not exist under {root!r}"
        )
    return fullpath


def resolve_confined_api_root(configured_root: str) -> str:
    """Resolve and validate a configured API root directory.

    Intended for server configuration (``BEHAVIORAL_SOURCE_API_ROOT``), not
    request-supplied paths.
    """
    configured_root = configured_root.strip()
    if not configured_root:
        raise ValueError("API root must be configured")
    try:
        root = os.path.realpath(configured_root)
    except OSError as exc:
        raise ValueError("Invalid API root path") from exc
    if not os.path.isdir(root):
        raise ValueError("API root is not a directory")
    return root


def confine_path(
    source_path: str | os.PathLike,
    resolved_root: str | os.PathLike,
    *,
    must_exist: bool = False,
) -> Path:
    """Resolve ``source_path`` and require it to stay inside ``resolved_root``.

    Only relative paths made of validated components are accepted. The
    caller's input is normalized into discrete segments before joining
    under ``resolved_root`` so untrusted request data never flows directly
    into :class:`pathlib.Path` constructors.

    When ``must_exist`` is true, raises :class:`ConfinedPathNotFoundError`
    if the confined path is missing. Existence checks belong here so API
    handlers do not perform filesystem operations on request-derived paths.
    """
    sanitized = sanitize_confined_path(source_path, resolved_root, must_exist=must_exist)
    return Path(sanitized)


def require_confined_path(
    source_path: str | os.PathLike,
    resolved_root: str | os.PathLike,
) -> str:
    """Like :func:`confine_path` but require the confined path to exist.

    Returns a sanitized absolute path string suitable for filesystem access.
    """
    return sanitize_confined_path(source_path, resolved_root, must_exist=True)


__all__ = [
    "ConfinedPathNotFoundError",
    "confine_path",
    "filter_safe_paths",
    "is_within_root",
    "require_confined_path",
    "resolve_confined_api_root",
    "safe_resolve_root",
    "sanitize_confined_path",
    "validate_confined_path_input",
]
