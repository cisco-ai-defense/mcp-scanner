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
"""Tests for the no-LLM YARA source scan (``mcp-scanner static-source``).

The ``behavioral`` scan path pairs static analysis with an LLM alignment
check and so cannot run without LLM credentials. These tests pin the
contract of the pattern-only path:

* it runs with **no** LLM provider key configured,
* it enumerates clean files as well as matching ones, so a scan reports
  what it examined rather than only what it flagged,
* a file whose YARA scan raises is surfaced as an error rather than being
  dropped or reported as clean, and
* the traversal it shares with the behavioural analyzer still refuses to
  follow symlinks that escape the scan root.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.source_discovery import find_source_files
from mcpscanner.core.source_scan import scan_source_with_yara

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def source_tree(tmp_path: Path) -> Path:
    """A small source tree with files that must and must not be scanned.

    Layout::

        root/
          server.py               <- scanned
          sub/clean.py            <- scanned
          handler.ts              <- scanned (non-Python extension)
          node_modules/dep.js     <- skipped (dependency tree)
          __pycache__/cached.py   <- skipped (build artefact)
          .hidden/secret.py       <- skipped (dot-directory)
          notes.txt               <- skipped (unsupported extension)
    """
    (tmp_path / "server.py").write_text("def handler():\n    return 1\n")
    (tmp_path / "handler.ts").write_text("export function h() { return 1; }\n")

    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "clean.py").write_text("VALUE = 2\n")

    for skipped_dir in ("node_modules", "__pycache__", ".hidden"):
        d = tmp_path / skipped_dir
        d.mkdir()
        (d / "dep.py").write_text("SHOULD_NOT_BE_SCANNED = True\n")
        (d / "dep.js").write_text("// should not be scanned\n")

    (tmp_path / "notes.txt").write_text("not source\n")
    return tmp_path


@pytest.fixture
def rules_dir(tmp_path_factory) -> Path:
    """A custom YARA rules directory whose single rule matches ``server.py``.

    Naming the rule lets a test assert that custom rules were actually
    loaded, rather than that the command merely exited zero.
    """
    d = tmp_path_factory.mktemp("rules")
    (d / "custom.yar").write_text(
        "rule custom_marker_rule {\n"
        "  meta:\n"
        '    description = "matches the fixture source tree"\n'
        '    threat_type = "custom_marker"\n'
        "  strings:\n"
        '    $a = "def handler"\n'
        "  condition:\n"
        "    $a\n"
        "}\n"
    )
    return d


def _rows_by_name(results: list[dict]) -> dict[str, dict]:
    return {row["tool_name"]: row for row in results}


# ---------------------------------------------------------------------------
# Source discovery
# ---------------------------------------------------------------------------


def test_find_source_files_selects_supported_extensions(source_tree: Path):
    """Python and tree-sitter-supported extensions are picked up."""
    found = {
        os.path.relpath(p, source_tree) for p in find_source_files(str(source_tree))
    }

    assert "server.py" in found
    assert os.path.join("sub", "clean.py") in found
    assert "handler.ts" in found


def test_find_source_files_skips_artefacts_and_unsupported(source_tree: Path):
    """Dependency trees, build artefacts, dot-dirs and non-source are skipped."""
    found = {
        os.path.relpath(p, source_tree) for p in find_source_files(str(source_tree))
    }

    assert not any(
        part in name
        for name in found
        for part in ("node_modules", "__pycache__", ".hidden")
    )
    assert "notes.txt" not in found


def test_find_source_files_rejects_symlink_escaping_root(tmp_path: Path):
    """A symlink whose target is outside the scan root is not returned.

    This is the shared-traversal half of the symlink-traversal hardening;
    the no-LLM path must not become a way to read arbitrary files.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("SECRET = 'do not read'\n")

    root = tmp_path / "root"
    root.mkdir()
    (root / "normal.py").write_text("OK = True\n")
    try:
        (root / "escape.py").symlink_to(secret)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks not supported on this platform")

    found = find_source_files(str(root))

    assert any(name.endswith("normal.py") for name in found)
    assert not any(name.endswith("escape.py") for name in found)
    assert not any("secret.py" in name for name in found)


# ---------------------------------------------------------------------------
# Scanning: no LLM credentials required
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_runs_without_llm_credentials(source_tree: Path, monkeypatch):
    """The scan completes with every LLM-related env var cleared.

    This is the regression that matters: the pattern-only path must not
    reach the alignment client, which raises ``ValueError`` when no
    provider key is configured.
    """
    for var in (
        "MCP_SCANNER_LLM_API_KEY",
        "MCP_SCANNER_LLM_MODEL",
        "MCP_SCANNER_LLM_BASE_URL",
        "AWS_BEARER_TOKEN_BEDROCK",
    ):
        monkeypatch.delenv(var, raising=False)

    results = await scan_source_with_yara(str(source_tree))

    assert results, "scan should report the files it examined"
    assert all("yara_analyzer" in row["findings"] for row in results)


@pytest.mark.asyncio
async def test_scan_enumerates_clean_files_as_safe(source_tree: Path):
    """Files with no rule match appear as SAFE rather than being omitted.

    A scan that only listed matches would make "examined and clean"
    indistinguishable from "never examined".
    """
    results = await scan_source_with_yara(str(source_tree))
    rows = _rows_by_name(results)

    assert "server.py" in rows
    clean_row = rows["server.py"]
    assert clean_row["is_safe"] is True
    assert clean_row["status"] == "completed"
    assert clean_row["findings"]["yara_analyzer"]["severity"] == "SAFE"
    assert clean_row["findings"]["yara_analyzer"]["total_findings"] == 0


@pytest.mark.asyncio
async def test_scan_reports_matches_as_unsafe(source_tree: Path):
    """A rule match yields an unsafe row carrying the finding's severity."""
    finding = SecurityFinding(
        severity="HIGH",
        summary="Detected 1 threat: script injection",
        analyzer="YARA",
        threat_category="INJECTION ATTACK",
        details={"tool_name": "server.py"},
    )

    async def fake_analyze(content, context=None):
        # Only the top-level server.py "matches"; everything else is clean.
        if context and context.get("tool_name") == "server.py":
            return [finding]
        return []

    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer.analyze",
        side_effect=fake_analyze,
    ):
        results = await scan_source_with_yara(str(source_tree))

    rows = _rows_by_name(results)
    assert rows["server.py"]["is_safe"] is False
    analyzer_data = rows["server.py"]["findings"]["yara_analyzer"]
    assert analyzer_data["severity"] == "HIGH"
    assert analyzer_data["threat_names"] == ["INJECTION ATTACK"]
    assert analyzer_data["total_findings"] == 1

    # Clean siblings are still enumerated alongside the match.
    assert rows[os.path.join("sub", "clean.py")]["is_safe"] is True


@pytest.mark.asyncio
async def test_scan_surfaces_analyzer_failure_instead_of_passing(source_tree: Path):
    """A file whose scan raises is reported as an error, never as clean.

    Swallowing the exception and emitting a SAFE row would make a failure
    to gather evidence look like evidence of safety.
    """

    async def boom(content, context=None):
        if context and context.get("tool_name") == "server.py":
            raise RuntimeError("rule matching blew up")
        return []

    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer.analyze",
        side_effect=boom,
    ):
        results = await scan_source_with_yara(str(source_tree))

    rows = _rows_by_name(results)
    failed = rows["server.py"]
    assert failed["status"] == "error"
    assert failed["is_safe"] is False
    assert failed["findings"]["yara_analyzer"]["severity"] == "UNKNOWN"
    assert (
        "rule matching blew up" in failed["findings"]["yara_analyzer"]["threat_summary"]
    )

    # One bad file must not abort the rest of the scan.
    assert rows[os.path.join("sub", "clean.py")]["is_safe"] is True


@pytest.mark.asyncio
async def test_scan_surfaces_unreadable_file_instead_of_omitting(source_tree: Path):
    """A file that cannot be read is reported, not silently dropped.

    Omitting it would let a permission-denied tree scan as clean.
    """
    target = str(source_tree / "server.py")

    real_open = open

    def deny(path, *args, **kwargs):
        if str(path) == target:
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    with patch("builtins.open", side_effect=deny):
        results = await scan_source_with_yara(str(source_tree))

    rows = _rows_by_name(results)
    failed = rows["server.py"]
    assert failed["status"] == "error"
    assert failed["is_safe"] is False
    assert failed["findings"]["yara_analyzer"]["severity"] == "UNKNOWN"
    assert "could not be read" in failed["findings"]["yara_analyzer"]["threat_summary"]

    # Readable siblings are still scanned.
    assert rows[os.path.join("sub", "clean.py")]["is_safe"] is True


@pytest.mark.asyncio
async def test_unexaminable_severity_is_renderable(source_tree: Path):
    """Error rows use a severity every formatter already knows how to render.

    ``by_severity`` iterates a fixed ordering, so a bespoke severity would
    drop the row and hide the very failure the error row exists to report.
    """
    from mcpscanner.core.report_generator import ReportGenerator
    from mcpscanner.core.models import OutputFormat, SeverityFilter

    async def boom(content, context=None):
        raise RuntimeError("nope")

    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer.analyze",
        side_effect=boom,
    ):
        results = await scan_source_with_yara(str(source_tree))

    rendered = ReportGenerator(
        {"server_url": "t", "scan_results": results}
    ).format_output(
        format_type=OutputFormat.BY_SEVERITY,
        severity_filter=SeverityFilter.ALL,
    )

    assert "server.py" in rendered


# ---------------------------------------------------------------------------
# Scanning: input shapes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_accepts_single_file(source_tree: Path):
    """A file path scans just that file, regardless of its extension filter."""
    target = source_tree / "server.py"
    results = await scan_source_with_yara(str(target))

    assert len(results) == 1
    assert results[0]["tool_name"] == "server.py"


@pytest.mark.asyncio
async def test_scan_empty_directory_reports_no_files(tmp_path: Path):
    """An empty tree yields an explicit placeholder row, not an empty list."""
    results = await scan_source_with_yara(str(tmp_path))

    assert len(results) == 1
    assert results[0]["tool_name"] == "No source files found"
    assert results[0]["is_safe"] is True


@pytest.mark.asyncio
async def test_scan_missing_path_raises(tmp_path: Path):
    """A nonexistent path is a caller error, surfaced as FileNotFoundError."""
    missing = tmp_path / "definitely-not-here"

    with pytest.raises(FileNotFoundError):
        await scan_source_with_yara(str(missing))


@pytest.mark.asyncio
async def test_scan_skips_oversized_files(source_tree: Path):
    """Files past the size ceiling are skipped rather than read into memory."""
    with patch(
        "mcpscanner.core.source_scan.MCPScannerConstants.MAX_FILE_SIZE_BYTES", 1
    ):
        results = await scan_source_with_yara(str(source_tree))

    assert len(results) == 1
    assert results[0]["tool_name"] == "No source files found"


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "argv_tail",
    [
        ["static-source", "SRC", "--rules-path", "RULES"],
        ["--rules-path", "RULES", "static-source", "SRC"],
    ],
    ids=["after-subcommand", "before-subcommand"],
)
async def test_cli_accepts_rules_path_either_side(
    source_tree: Path, rules_dir: Path, argv_tail, capsys
):
    """``--rules-path`` works on both sides of the subcommand.

    It is registered globally *and* on the subparser; the subparser uses
    ``SUPPRESS`` so it cannot clobber a value given before the subcommand.
    """
    from mcpscanner.cli import main

    argv = ["mcp-scanner"] + [
        str(source_tree) if a == "SRC" else str(rules_dir) if a == "RULES" else a
        for a in argv_tail
    ]
    # Raw output carries the matched rule name, so this asserts the custom
    # rules were actually compiled rather than that the command merely exited.
    argv += ["--format", "raw"]

    with patch("sys.argv", argv):
        await main()

    assert "custom marker rule" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_cli_credits_only_yara_in_table(source_tree: Path, capsys):
    """``--format table`` must not report API/LLM as SAFE for this mode.

    Neither analyzer runs here, so claiming a verdict for them would assert
    a clean result from a check that never executed.
    """
    from mcpscanner.cli import main

    argv = ["mcp-scanner", "static-source", str(source_tree), "--format", "table"]
    with patch("sys.argv", argv):
        await main()

    rows = [
        line
        for line in capsys.readouterr().out.splitlines()
        if "server.py" in line or "clean.py" in line
    ]
    assert rows, "expected at least one rendered result row"
    # YARA ran, so it reports SAFE; API and LLM did not, so they must be N/A.
    for row in rows:
        assert "SAFE" in row
        assert row.count("N/A") == 2
