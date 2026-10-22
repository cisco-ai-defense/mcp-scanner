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


def test_elf_txt_is_skipped_when_puremagic_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(file_magic, "_PUREMAGIC_AVAILABLE", False)
    path = tmp_path / "payload.txt"
    path.write_bytes(_ELF_HEADER)

    assert file_magic.detect_magic(str(path)) is None
    analyzer = VirusTotalAnalyzer()
    assert analyzer._should_scan_file(str(path)) is False
