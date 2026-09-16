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

"""Tests for magic-byte detection.

Detection decides whether a scanner treats a payload as source text or
as an opaque binary, so the cases that matter are the ones where a file
lies about itself: a .pyc named .py, an executable with no extension,
and anything that makes detection fail without saying so.
"""

from unittest.mock import patch

import pytest

from mcpscanner.utils.file_magic import (
    MagicResult,
    _classify_family,
    detect_magic,
    detect_magic_bytes,
    is_puremagic_available,
)

pytestmark = pytest.mark.skipif(
    not is_puremagic_available(), reason="puremagic is not installed"
)


class TestClassifyFamily:
    @pytest.mark.parametrize(
        "mime,family",
        [
            ("text/plain", "text"),
            ("text/html", "text"),
            ("application/json", "text"),
            ("application/xml", "text"),
            ("application/x-python", "text"),
            ("application/x-shellscript", "text"),
            ("image/png", "image"),
            ("audio/mpeg", "audio"),
            ("video/mp4", "video"),
            ("application/zip", "application"),
            ("application/x-python-bytecode", "application"),
        ],
    )
    def test_known_mimes_map_to_their_family(self, mime, family):
        assert _classify_family(mime) == family

    def test_empty_mime_is_unknown(self):
        assert _classify_family("") == "unknown"
        assert _classify_family(None) == "unknown"

    def test_matching_is_case_insensitive(self):
        assert _classify_family("IMAGE/PNG") == "image"
        assert _classify_family("Application/JSON") == "text"

    def test_unrecognised_mime_defaults_to_application(self):
        """Unknown types must not be assumed to be safe text."""
        assert _classify_family("x-custom/whatever") == "application"


class TestDetectMagicBytes:
    def test_png_signature_is_recognised(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        result = detect_magic_bytes(png)
        assert result is not None
        assert result.content_family == "image"
        assert "png" in result.mime_type.lower()

    def test_gzip_signature_is_recognised(self):
        result = detect_magic_bytes(b"\x1f\x8b\x08" + b"\x00" * 64)
        assert result is not None
        assert result.content_family == "application"

    def test_plain_text_has_no_signature(self):
        assert detect_magic_bytes(b"just some ordinary text\n") is None

    def test_empty_input_has_no_signature(self):
        assert detect_magic_bytes(b"") is None

    def test_detection_failure_returns_none_rather_than_raising(self):
        with patch("puremagic.magic_string", side_effect=ValueError("bad input")):
            assert detect_magic_bytes(b"\x89PNG\r\n\x1a\n") is None

    def test_result_is_immutable(self):
        result = detect_magic_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        with pytest.raises(Exception):
            result.mime_type = "text/plain"


class TestDetectMagic:
    def test_png_file_is_recognised(self, tmp_path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        result = detect_magic(str(f))
        assert result is not None
        assert result.content_family == "image"

    def test_extension_does_not_override_the_bytes(self, tmp_path):
        """A binary wearing a .py extension must still read as binary."""
        f = tmp_path / "innocent.py"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        result = detect_magic(str(f))
        assert result is not None
        assert result.content_family == "image"

    def test_source_file_is_classified_as_text(self, tmp_path):
        """Unlike the bytes API, the path API also consults the extension."""
        f = tmp_path / "script.py"
        f.write_text("print('hello')\n")
        result = detect_magic(str(f))
        assert result is not None
        assert result.content_family == "text"

    def test_extensionless_text_has_no_signature(self, tmp_path):
        f = tmp_path / "notes"
        f.write_text("just prose, no magic bytes\n")
        assert detect_magic(str(f)) is None

    def test_missing_file_returns_none_rather_than_raising(self, tmp_path):
        assert detect_magic(str(tmp_path / "nope.bin")) is None

    def test_empty_file_returns_none(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert detect_magic(str(f)) is None

    def test_match_without_a_mime_type_is_discarded(self, tmp_path):
        """A signature with no MIME is too weak to act on."""
        f = tmp_path / "thing.bin"
        f.write_bytes(b"\x00" * 32)

        class Weak:
            mime_type = ""
            extension = ".bin"
            name = "weak guess"

        with patch("puremagic.magic_file", return_value=[Weak()]):
            assert detect_magic(str(f)) is None

    def test_best_match_wins_when_several_are_returned(self, tmp_path):
        f = tmp_path / "thing.bin"
        f.write_bytes(b"\x00" * 32)

        class Match:
            def __init__(self, mime):
                self.mime_type = mime
                self.extension = ".x"
                self.name = mime

        with patch(
            "puremagic.magic_file",
            return_value=[Match("image/png"), Match("audio/mpeg")],
        ):
            assert detect_magic(str(f)).content_family == "image"


class TestPythonBytecodeSignatures:
    """.pyc files are registered manually; puremagic does not know them."""

    @pytest.mark.parametrize("header", [b"\xa7\r\r\n", b"\xcb\r\r\n", b"\xef\r\r\n"])
    def test_modern_pyc_headers_are_detected_as_bytecode(self, header):
        result = detect_magic_bytes(header + b"\x00" * 64)
        assert result is not None
        assert result.mime_type == "application/x-python-bytecode"
        assert result.content_family == "application"

    def test_bytecode_is_not_mistaken_for_text(self, tmp_path):
        f = tmp_path / "module.pyc"
        f.write_bytes(b"\xcb\r\r\n" + b"\x00" * 64)
        assert detect_magic(str(f)).content_family != "text"


class TestGracefulDegradation:
    def test_detection_is_disabled_when_puremagic_is_absent(self):
        with patch("mcpscanner.utils.file_magic._PUREMAGIC_AVAILABLE", False):
            assert detect_magic("/any/path") is None
            assert detect_magic_bytes(b"\x89PNG\r\n\x1a\n") is None


class TestMagicResult:
    def test_fields_round_trip(self):
        r = MagicResult("image/png", ".png", "PNG image", "image")
        assert (r.mime_type, r.extension, r.name, r.content_family) == (
            "image/png",
            ".png",
            "PNG image",
            "image",
        )
