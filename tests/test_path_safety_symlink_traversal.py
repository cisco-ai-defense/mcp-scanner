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
"""Regression tests for the symlink-traversal hardening in directory scans.

These tests cover both directly-affected analyzers
(``BehavioralCodeAnalyzer`` and ``VirusTotalAnalyzer``) plus the shared
``mcpscanner.utils.path_safety`` helper. The vulnerability they protect
against:

    A scanned directory contains a file symlink whose target lies outside
    the scan root. ``Path.rglob`` matches it; ``open()`` / ``Path.read_*``
    follows the link; the analyzer ingests (and, for VT with uploads
    enabled, exfiltrates) a file outside the user-selected scope.

The fix is to resolve every candidate path and reject anything whose
canonical location escapes the scan root. Intra-root symlinks are still
allowed — they are common in legitimate trees (e.g. ``node_modules/.bin``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from mcpscanner.core.analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer
from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from mcpscanner.utils.path_safety import (
    filter_safe_paths,
    is_within_root,
    safe_resolve_root,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def hostile_layout(tmp_path: Path) -> dict:
    """Build a scanroot containing one benign file and one malicious symlink.

    Layout::

        tmp_path/
          outside/
            secret.py            <- target of the escape
          scanroot/
            normal_tool.py       <- benign, in-tree
            innocent_looking.py  -> ../outside/secret.py    (file symlink, ESCAPES)

    Returns a dict with the relevant paths so individual tests can pick
    what they need.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("EXFIL_SECRET = 'should-never-be-read'\n")

    scanroot = tmp_path / "scanroot"
    scanroot.mkdir()
    benign = scanroot / "normal_tool.py"
    benign.write_text("def hello():\n    return 'hi'\n")

    escape = scanroot / "innocent_looking.py"
    os.symlink(secret, escape)

    return {
        "tmp": tmp_path,
        "scanroot": scanroot,
        "benign": benign,
        "escape_link": escape,
        "secret_target": secret,
    }


@pytest.fixture
def intra_root_layout(tmp_path: Path) -> dict:
    """Layout with a symlink that stays inside the scan root. Must NOT be skipped."""
    scanroot = tmp_path / "scanroot"
    scanroot.mkdir()

    real = scanroot / "real.py"
    real.write_text("X = 1\n")

    link = scanroot / "alias.py"
    os.symlink(real, link)

    nested = scanroot / "pkg"
    nested.mkdir()
    nested_link = nested / "shortcut.py"
    os.symlink(real, nested_link)

    return {
        "scanroot": scanroot,
        "real": real,
        "alias": link,
        "nested_alias": nested_link,
    }


@pytest.fixture
def broken_link_layout(tmp_path: Path) -> dict:
    """Layout with a dangling symlink — must not raise, must be filtered."""
    scanroot = tmp_path / "scanroot"
    scanroot.mkdir()
    real = scanroot / "ok.py"
    real.write_text("ok = True\n")

    dangling = scanroot / "dangling.py"
    os.symlink(tmp_path / "does_not_exist.py", dangling)
    return {"scanroot": scanroot, "real": real, "dangling": dangling}


# ---------------------------------------------------------------------------
# Helper-level tests
# ---------------------------------------------------------------------------


class TestPathSafetyHelper:
    def test_safe_resolve_root_returns_absolute_canonical(self, tmp_path: Path):
        rel = tmp_path / "x"
        rel.mkdir()
        resolved = safe_resolve_root(str(rel))
        assert resolved.is_absolute()
        assert resolved == rel.resolve()

    def test_is_within_root_accepts_in_tree(self, tmp_path: Path):
        root = safe_resolve_root(str(tmp_path))
        f = tmp_path / "child.py"
        f.write_text("")
        assert is_within_root(f, root) is True

    def test_is_within_root_rejects_escape_via_symlink(self, hostile_layout):
        root = safe_resolve_root(str(hostile_layout["scanroot"]))
        assert is_within_root(hostile_layout["escape_link"], root) is False

    def test_is_within_root_rejects_unrelated_absolute_path(self, tmp_path: Path):
        root = safe_resolve_root(str(tmp_path / "scanroot"))
        # ``/etc/passwd`` is the canonical example of a sensitive
        # out-of-tree file; we just need any path that is definitely not
        # under ``root``.
        assert is_within_root(Path("/etc/passwd"), root) is False

    def test_is_within_root_handles_resolution_error_safely(self, tmp_path: Path):
        # Simulate a path object whose ``resolve`` raises — represent it
        # via a broken symlink that resolve() handles fine in 3.11+, so we
        # construct a resolution-failing scenario differently: pass a path
        # under a directory that has been deleted. Should not raise.
        root = safe_resolve_root(str(tmp_path))
        bogus = tmp_path / "missing" / "x"  # parent doesn't exist
        # ``resolve(strict=False)`` will succeed; just make sure no crash.
        assert isinstance(is_within_root(bogus, root), bool)

    def test_filter_safe_paths_separates_safe_and_skipped(self, hostile_layout, caplog):
        root = safe_resolve_root(str(hostile_layout["scanroot"]))
        candidates = [hostile_layout["benign"], hostile_layout["escape_link"]]

        with caplog.at_level("WARNING"):
            safe, skipped = filter_safe_paths(
                candidates, root, audit_label="unit-test"
            )

        assert hostile_layout["benign"] in safe
        assert hostile_layout["escape_link"] not in safe
        assert skipped == 1

        # The audit log must call out the symlink that escaped.
        warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
        assert any("symlink that escapes scan root" in w for w in warnings)
        # And it must NOT echo the resolved escape target at WARNING — we
        # don't want to mirror sensitive paths into shared log streams.
        assert not any(
            str(hostile_layout["secret_target"]) in w for w in warnings
        )


# ---------------------------------------------------------------------------
# BehavioralCodeAnalyzer
# ---------------------------------------------------------------------------


class TestBehavioralCodeAnalyzerSymlinkSafety:
    """Verify the source-file discovery path no longer ingests escapes."""

    def _new_analyzer(self) -> BehavioralCodeAnalyzer:
        # The analyzer's __init__ pulls in heavy LLM/static-analysis state
        # we don't need here; the discovery method is pure.
        return BehavioralCodeAnalyzer.__new__(BehavioralCodeAnalyzer)

    def test_escape_symlink_is_not_returned_by_find_source_files(
        self, hostile_layout
    ):
        analyzer = self._new_analyzer()
        files = analyzer._find_source_files(str(hostile_layout["scanroot"]))

        assert str(hostile_layout["benign"]) in files
        assert str(hostile_layout["escape_link"]) not in files

    def test_escape_symlink_is_not_returned_by_find_python_files(
        self, hostile_layout
    ):
        analyzer = self._new_analyzer()
        files = analyzer._find_python_files(str(hostile_layout["scanroot"]))

        assert str(hostile_layout["benign"]) in files
        assert str(hostile_layout["escape_link"]) not in files

    def test_intra_root_symlinks_are_still_returned(self, intra_root_layout):
        analyzer = self._new_analyzer()
        files = analyzer._find_source_files(str(intra_root_layout["scanroot"]))

        assert str(intra_root_layout["real"]) in files
        # In-tree symlinks must still be picked up; they are a legitimate
        # pattern (vendored bins, fixtures, etc.) and rejecting them would
        # silently shrink scan coverage.
        assert str(intra_root_layout["alias"]) in files
        assert str(intra_root_layout["nested_alias"]) in files

    def test_broken_symlink_does_not_crash(self, broken_link_layout):
        analyzer = self._new_analyzer()
        files = analyzer._find_source_files(str(broken_link_layout["scanroot"]))
        # ``ok.py`` survives; the dangling link is dropped without exception.
        assert str(broken_link_layout["real"]) in files
        assert str(broken_link_layout["dangling"]) not in files


# ---------------------------------------------------------------------------
# VirusTotalAnalyzer
# ---------------------------------------------------------------------------


class TestVirusTotalAnalyzerSymlinkSafety:
    """``_discover_files`` must reject escapes before anything is hashed
    or uploaded. This covers the higher-impact half of the disclosure:
    with ``vt_scan_files`` enabled, an unfiltered escape would be
    uploaded to a third-party service."""

    def _new_analyzer(self) -> VirusTotalAnalyzer:
        return VirusTotalAnalyzer.__new__(VirusTotalAnalyzer)

    def test_escape_symlink_is_not_discovered(self, hostile_layout):
        analyzer = self._new_analyzer()
        files = analyzer._discover_files(str(hostile_layout["scanroot"]))

        assert str(hostile_layout["benign"]) in files
        assert str(hostile_layout["escape_link"]) not in files

    def test_intra_root_symlinks_are_still_discovered(self, intra_root_layout):
        analyzer = self._new_analyzer()
        files = analyzer._discover_files(str(intra_root_layout["scanroot"]))

        assert str(intra_root_layout["real"]) in files
        assert str(intra_root_layout["alias"]) in files
        assert str(intra_root_layout["nested_alias"]) in files

    def test_broken_symlink_does_not_crash(self, broken_link_layout):
        analyzer = self._new_analyzer()
        files = analyzer._discover_files(str(broken_link_layout["scanroot"]))
        assert str(broken_link_layout["real"]) in files
        assert str(broken_link_layout["dangling"]) not in files

    def test_directory_symlink_pointing_outside_is_not_recursed(
        self, tmp_path: Path
    ):
        """Defence-in-depth: even if a future ``rglob`` flag flips and
        starts following directory symlinks, the per-file resolution
        check here will still drop everything under an escaping link."""
        outside = tmp_path / "outside_lib"
        outside.mkdir()
        (outside / "leaked.py").write_text("LEAK = 1\n")

        scanroot = tmp_path / "scanroot"
        scanroot.mkdir()
        (scanroot / "normal.py").write_text("ok = 1\n")
        os.symlink(outside, scanroot / "vendored")

        analyzer = self._new_analyzer()
        files = analyzer._discover_files(str(scanroot))

        # The benign in-tree file is present.
        assert str(scanroot / "normal.py") in files
        # Nothing under the escaping directory symlink leaks in, even if
        # an underlying glob implementation chose to recurse it.
        assert not any("outside_lib" in f for f in files)
        assert not any("leaked.py" in f for f in files)


# ---------------------------------------------------------------------------
# Symlink-cycle safety
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Symlink cycle creation is unreliable on Windows CI runners.",
)
def test_symlink_cycle_does_not_hang_or_crash(tmp_path: Path):
    """A symlink cycle inside the scan root must not cause unbounded
    work or an unhandled ``OSError`` from ``resolve()``."""
    scanroot = tmp_path / "scanroot"
    scanroot.mkdir()
    (scanroot / "real.py").write_text("ok = 1\n")

    a = scanroot / "loop_a"
    b = scanroot / "loop_b"
    os.symlink(b, a)
    os.symlink(a, b)

    analyzer = BehavioralCodeAnalyzer.__new__(BehavioralCodeAnalyzer)
    files = analyzer._find_source_files(str(scanroot))

    # ``real.py`` is returned; the cycle members do not cause an exception.
    assert str(scanroot / "real.py") in files
