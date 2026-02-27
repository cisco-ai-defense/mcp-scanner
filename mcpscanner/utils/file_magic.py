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
    logger.debug(
        "puremagic is not installed — magic-byte detection disabled. "
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


def detect_magic(file_path: str) -> Optional[MagicResult]:
    """
    Detect file type using magic bytes via puremagic.

    Args:
        file_path: Path to the file to inspect.

    Returns:
        MagicResult if a signature was found, None otherwise.
        Returns None when puremagic is not installed (graceful fallback).
    """
    if not _PUREMAGIC_AVAILABLE:
        return None

    try:
        matches = puremagic.magic_file(file_path)
        if not matches:
            return None

        # puremagic returns a list of matches sorted by confidence; take the best
        best = matches[0]
        mime = best.mime_type or ""
        ext = best.extension or ""
        name = best.name or ""

        # If MIME is empty, the match is low-confidence — treat as no match
        if not mime:
            return None

        return MagicResult(
            mime_type=mime,
            extension=ext,
            name=name,
            content_family=_classify_family(mime),
        )
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
        matches = puremagic.magic_string(data)
        if not matches:
            return None

        best = matches[0]
        mime = best.mime_type or ""
        ext = best.extension or ""
        name = best.name or ""

        return MagicResult(
            mime_type=mime,
            extension=ext,
            name=name,
            content_family=_classify_family(mime),
        )
    except Exception as exc:
        logger.debug("Magic-byte detection failed for bytes: %s", exc)
        return None


def is_puremagic_available() -> bool:
    """Check if puremagic is installed and available."""
    return _PUREMAGIC_AVAILABLE
