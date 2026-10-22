# Copyright 2026 Cisco Systems, Inc.
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
"""
Thin wrapper around ``puremagic`` for magic-byte file type detection.

Provides:
  - ``detect_magic(path)`` → ``MagicResult | None``
  - Graceful fallback when puremagic is not installed
  - Custom signatures for formats puremagic doesn't cover (e.g. Python bytecode)

Usage::

    from mcpscanner.core.analyzers.file_magic import detect_magic

    result = detect_magic("/path/to/file")
    if result and result.content_family != "text":
        print("Non-text file detected:", result.mime_type)
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional puremagic import
# ---------------------------------------------------------------------------

_PUREMAGIC_AVAILABLE = False
try:
    import puremagic

    _PUREMAGIC_AVAILABLE = True
except ImportError:
    logger.warning(
        "puremagic is not installed — magic-byte detection disabled. "
        "Files with a text extension will be skipped without a content check. "
        "Install with: pip install puremagic"
    )

# ---------------------------------------------------------------------------
# Custom signatures (registered once at import time)
# ---------------------------------------------------------------------------

if _PUREMAGIC_AVAILABLE:
    try:
        from puremagic import PureMagic, magic_header_array

        _CUSTOM_SIGNATURES = [
            # Python bytecode variants not in puremagic's database
            (b"\xa7\r\r\n", 0, ".pyc", "application/x-python-bytecode", "Python 3.11 bytecode"),
            (b"\xcb\r\r\n", 0, ".pyc", "application/x-python-bytecode", "Python 3.12 bytecode"),
            (b"\xef\r\r\n", 0, ".pyc", "application/x-python-bytecode", "Python 3.13 bytecode"),
        ]
        _existing = {e.byte_match for e in magic_header_array}
        for bm, off, ext, mime, name in _CUSTOM_SIGNATURES:
            if bm not in _existing:
                magic_header_array.append(
                    PureMagic(
                        byte_match=bm,
                        offset=off,
                        extension=ext,
                        mime_type=mime,
                        name=name,
                    )
                )
        logger.debug("Registered %d custom magic signatures", len(_CUSTOM_SIGNATURES))
    except Exception as exc:
        logger.debug("Failed to register custom magic signatures: %s", exc)


# ---------------------------------------------------------------------------
# Content family mapping
# ---------------------------------------------------------------------------

# MIME prefixes / patterns → content family
_FAMILY_MAP = {
    "text/": "text",
    "application/json": "text",
    "application/xml": "text",
    "application/javascript": "text",
    "application/x-yaml": "text",
    "application/toml": "text",
    "application/x-sh": "text",
    "application/x-shellscript": "text",
    "application/x-python": "text",
    "application/x-ruby": "text",
    "application/x-perl": "text",
    "application/x-php": "text",
}


def _classify_family(mime_type: str) -> str:
    """Map a MIME type to a content family (text, image, audio, video, application, etc.)."""
    if not mime_type:
        return "unknown"
    mime_lower = mime_type.lower()
    # Check exact matches first
    for pattern, family in _FAMILY_MAP.items():
        if pattern.endswith("/"):
            if mime_lower.startswith(pattern):
                return family
        elif mime_lower == pattern:
            return family
    # Broad categories
    if mime_lower.startswith("image/"):
        return "image"
    if mime_lower.startswith("audio/"):
        return "audio"
    if mime_lower.startswith("video/"):
        return "video"
    return "application"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MagicResult:
    """Result of a magic-byte detection."""
    mime_type: str
    extension: str
    name: str
    content_family: str  # "text", "image", "audio", "video", "application", "unknown"


# Names puremagic gives text files when it leaves the MIME empty.
# "UTF8 file" is one of these; treating every empty-MIME name as a binary
# made a normal BOM text file look like an executable.
_TEXT_MAGIC_NAMES = frozenset(
    {
        "utf8 file",
        "utf-8 file",
        "text file",
        "ascii file",
        "unicode text file",
    }
)

# Signatures that stay distinctive inside a text prefix. MZ/PK are not here:
# those two-byte values show up in ordinary prose.
_EMBEDDED_EXECUTABLE_SIGNATURES = (
    b"\x7fELF",  # ELF
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit, reversed
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit, reversed
    b"\xca\xfe\xba\xbe",  # Mach-O fat / Java class
    b"\xbe\xba\xfe\xca",  # Mach-O fat, reversed
)
# How far past the start a text prefix can hide one of those signatures.
_EMBEDDED_SCAN_BYTES = 65536


def _family_for_empty_mime(name: str) -> str:
    """Classify a named puremagic hit that did not include a MIME type."""
    lowered = name.lower()
    if lowered in _TEXT_MAGIC_NAMES or lowered.startswith("utf"):
        return "text"
    return "application"


def _is_bare_uuencode_match(mime: str, name: str) -> bool:
    """True for puremagic's malformed ``begin`` hit.

    The byte string ``begin`` with no following space is reported as
    ``UUencoded file`` and an empty MIME. A real header (``begin 644 ``)
    is a different match, ``text/x-uuencode``, and must not be folded into
    this one.
    """
    return not mime and name.lower() == "uuencoded file"


def file_has_uuencode_header(file_path: str) -> bool:
    """Return True when the file starts with ``begin <octal-mode> ``.

    Mode is 3 or 4 octal digits. A bare ``begin`` or ``begin the …`` does
    not match, so ordinary prose is not selected for upload.
    """
    try:
        with open(file_path, "rb") as handle:
            header = handle.read(16)
    except OSError:
        return False
    if not header.startswith(b"begin "):
        return False
    rest = header[6:]
    mode_len = 0
    while mode_len < len(rest) and rest[mode_len : mode_len + 1] in b"01234567":
        mode_len += 1
    if mode_len not in (3, 4):
        return False
    return mode_len < len(rest) and rest[mode_len : mode_len + 1] == b" "


def file_contains_executable_signature(
    file_path: str, limit: int = _EMBEDDED_SCAN_BYTES
) -> bool:
    """Return True if a binary signature appears in the first ``limit`` bytes.

    puremagic stops at the text prefix and reports ``text/plain``, so an ELF
    or Mach-O header a few bytes in is invisible to ``detect_magic``.
    """
    try:
        with open(file_path, "rb") as handle:
            blob = handle.read(limit)
    except OSError:
        return False
    return any(signature in blob for signature in _EMBEDDED_EXECUTABLE_SIGNATURES)


def _result_from_matches(matches) -> Optional[MagicResult]:
    """Turn puremagic matches into a MagicResult.

    A best match that has a name or extension but no MIME is kept and
    classified as non-text. puremagic reports ELF that way ("ELF executable",
    empty MIME). Discarding it made ``detect_magic`` return None, and the
    VirusTotal selector then treated a ``.txt`` file as confirmed text.
    """
    if not matches:
        return None

    best = matches[0]
    mime = best.mime_type or ""
    ext = best.extension or ""
    name = best.name or ""
    # The bare ``begin`` hit has a name and no MIME. Keeping it would mark
    # a .txt file as a binary. Drop only that hit; a later text/x-uuencode
    # match, when present, still describes a real uuencode header.
    if not mime and (name or ext) and not _is_bare_uuencode_match(mime, name):
        return MagicResult(
            mime_type="",
            extension=ext,
            name=name,
            content_family=_family_for_empty_mime(name),
        )
    if not mime or _is_bare_uuencode_match(mime, name):
        for later in matches[1:]:
            later_mime = later.mime_type or ""
            later_name = later.name or ""
            if not later_mime or _is_bare_uuencode_match(later_mime, later_name):
                continue
            return MagicResult(
                mime_type=later_mime,
                extension=later.extension or "",
                name=later_name,
                content_family=_classify_family(later_mime),
            )
        return None
    return MagicResult(
        mime_type=mime,
        extension=ext,
        name=name,
        content_family=_classify_family(mime),
    )


def detect_magic(file_path: str) -> Optional[MagicResult]:
    """
    Detect file type using magic bytes via puremagic.

    Args:
        file_path: Path to the file to inspect.

    Returns:
        MagicResult if a signature was found, None otherwise.
        Returns None when puremagic is not installed (graceful fallback).
        A named signature with an empty MIME is still a result, classified
        as non-text.
    """
    if not _PUREMAGIC_AVAILABLE:
        return None

    try:
        return _result_from_matches(puremagic.magic_file(file_path))
    except Exception as exc:
        logger.debug("Magic-byte detection failed for %s: %s", file_path, exc)
        return None


def detect_magic_bytes(data: bytes) -> Optional[MagicResult]:
    """
    Detect file type from raw bytes using magic bytes via puremagic.

    Args:
        data: Raw bytes to inspect (at least first 1024 bytes recommended).

    Returns:
        MagicResult if a signature was found, None otherwise.
    """
    if not _PUREMAGIC_AVAILABLE:
        return None

    try:
        return _result_from_matches(puremagic.magic_string(data))
    except Exception as exc:
        logger.debug("Magic-byte detection failed for bytes: %s", exc)
        return None


def is_puremagic_available() -> bool:
    """Check if puremagic is installed and available."""
    return _PUREMAGIC_AVAILABLE
