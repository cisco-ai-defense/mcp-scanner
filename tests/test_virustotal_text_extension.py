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
"""VirusTotal file selection for a binary signature behind a text extension.

puremagic's ELF match has a name and an empty MIME. That used to be discarded,
so a ``.txt`` file was skipped as if it were text.
"""

from __future__ import annotations

import pytest

from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from mcpscanner.utils import file_magic

# ELF magic plus padding. Not a runnable binary; enough for the signature.
_ELF_HEADER = b"\x7fELF" + b"\x00" * 64


def test_elf_txt_is_scanned_when_puremagic_is_installed(tmp_path):
    pytest.importorskip("puremagic")
    path = tmp_path / "payload.txt"
    path.write_bytes(_ELF_HEADER)

    result = file_magic.detect_magic(str(path))
    assert result is not None
    assert result.content_family != "text"
    assert result.name

    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is True


def test_plain_txt_is_not_scanned(tmp_path):
    pytest.importorskip("puremagic")
    path = tmp_path / "notes.txt"
    path.write_text("hello\n", encoding="utf-8")

    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is False


def test_elf_txt_is_scanned_when_puremagic_is_unavailable(tmp_path, monkeypatch):
    """The embedded ELF check does not depend on puremagic."""
    monkeypatch.setattr(file_magic, "_PUREMAGIC_AVAILABLE", False)
    path = tmp_path / "payload.txt"
    path.write_bytes(_ELF_HEADER)

    assert file_magic.detect_magic(str(path)) is None
    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is True


@pytest.mark.parametrize(
    "prefix",
    [b"\n", b" ", b"hello\n", b"\xef\xbb\xbf"],
)
def test_elf_after_a_text_prefix_is_scanned(tmp_path, prefix):
    pytest.importorskip("puremagic")
    path = tmp_path / "payload.txt"
    path.write_bytes(prefix + _ELF_HEADER)

    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is True


def test_bom_text_is_not_scanned(tmp_path):
    """A UTF-8 BOM is a named empty-MIME match and must stay text."""
    pytest.importorskip("puremagic")
    path = tmp_path / "notes.txt"
    path.write_bytes(b"\xef\xbb\xbfhello\n")

    result = file_magic.detect_magic(str(path))
    assert result is not None
    assert result.content_family == "text"

    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is False


def test_bare_begin_is_not_scanned(tmp_path):
    """``begin`` with no mode is puremagic's empty-MIME uuencode hit."""
    pytest.importorskip("puremagic")
    path = tmp_path / "notes.txt"
    path.write_bytes(b"begin\nthis is a sentence about the beginning.\n")

    result = file_magic.detect_magic(str(path))
    assert result is None or result.content_family == "text"

    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is False


def test_uuencode_header_is_scanned(tmp_path):
    """A real ``begin <mode> <name>`` header is still selected."""
    pytest.importorskip("puremagic")
    path = tmp_path / "payload.txt"
    path.write_bytes(b"begin 644 payload.bin\nM5&AE(&AA\n`\nend\n")

    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is True


def test_uuencode_header_without_filename_is_not_scanned(tmp_path):
    """``begin 644`` with only a newline is not a complete header."""
    pytest.importorskip("puremagic")
    path = tmp_path / "notes.txt"
    path.write_bytes(b"begin 644 \n")

    assert file_magic.file_has_uuencode_header(str(path)) is False
    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is False


def test_begin_prose_is_not_scanned(tmp_path):
    pytest.importorskip("puremagic")
    path = tmp_path / "notes.txt"
    path.write_bytes(b"begin the report with a summary.\n")

    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is False


def test_elf_past_the_scan_window_is_not_scanned(tmp_path):
    pytest.importorskip("puremagic")
    path = tmp_path / "payload.txt"
    path.write_bytes(b" " * file_magic._EMBEDDED_SCAN_BYTES + _ELF_HEADER)

    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is False
