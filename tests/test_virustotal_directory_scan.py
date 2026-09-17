# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Orchestration behavior of VirusTotalAnalyzer.analyze_directory.

The analyzer is a 980-line module with no direct tests. What matters here
is not the HTTP plumbing (stubbed out) but the bookkeeping around it: the
max_files cap, the decision to abandon a scan once VirusTotal starts
refusing requests, and the per-file tallies that end up in
``last_scan_summary``. Those counters are the only record a caller gets of
what was and was not actually checked, so a file silently counted as
"clean" when it was really "throttled" is a reported-safe-but-unscanned
bug.
"""

from __future__ import annotations

import pytest

from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer


@pytest.fixture
def analyzer(tmp_path, monkeypatch):
    """An enabled analyzer whose file discovery and VT calls are stubbed."""
    vt = VirusTotalAnalyzer(api_key="k", enabled=True, max_files=0)
    vt._calculate_sha256 = lambda p: f"hash-of-{p.name}"
    vt._should_scan_file = lambda f: True
    return vt


def _files(analyzer, root, names):
    paths = [str(root / n) for n in names]
    analyzer._discover_files = lambda directory: paths
    return paths


def _vt_returns(analyzer, by_hash):
    """Stub the cached VT lookup: hash suffix -> (result, found, error)."""

    def query(file_hash):
        return by_hash[file_hash.removeprefix("hash-of-")]

    analyzer._query_virustotal_cached = query


def _clean(total=70):
    return ({"total_engines": total, "malicious": 0, "suspicious": 0}, True, None)


def _malicious(n=3, total=70):
    return ({"total_engines": total, "malicious": n, "suspicious": 0}, True, None)


def _suspicious(n=2, total=70):
    return ({"total_engines": total, "malicious": 0, "suspicious": n}, True, None)


NOT_FOUND = (None, False, None)


def test_clean_and_malicious_files_are_tallied_separately(analyzer, tmp_path):
    _files(analyzer, tmp_path, ["a.exe", "b.exe"])
    _vt_returns(analyzer, {"a.exe": _clean(), "b.exe": _malicious()})

    findings = analyzer.analyze_directory(str(tmp_path))

    assert len(findings) == 1
    assert analyzer.last_scan_summary["clean"] == 1
    assert analyzer.last_scan_summary["malicious"] == 1
    assert analyzer.last_scan_summary["scanned"] == 2
    assert analyzer.validated_files == ["a.exe"]


def test_suspicious_only_file_is_neither_clean_nor_a_finding(analyzer, tmp_path):
    # Suspicious-but-not-malicious is deliberately not a finding, but it
    # must not be recorded as validated either.
    _files(analyzer, tmp_path, ["s.exe"])
    _vt_returns(analyzer, {"s.exe": _suspicious()})

    findings = analyzer.analyze_directory(str(tmp_path))

    assert findings == []
    assert analyzer.validated_files == []
    assert analyzer.last_scan_summary["clean"] == 0
    assert analyzer.last_scan_summary["malicious"] == 0
    assert analyzer.last_scan_summary["scanned"] == 1


@pytest.mark.parametrize("reason", ["rate_limit", "quota_exceeded", "auth_error"])
def test_refusal_abandons_the_rest_of_the_scan(analyzer, tmp_path, reason):
    """Once VT refuses, remaining files count as throttled, not clean."""
    _files(analyzer, tmp_path, ["a.exe", "b.exe", "c.exe"])
    _vt_returns(
        analyzer,
        {"a.exe": _clean(), "b.exe": (None, False, reason), "c.exe": _clean()},
    )

    analyzer.analyze_directory(str(tmp_path))

    assert analyzer.last_scan_summary["scanned"] == 1
    assert analyzer.last_scan_summary["throttled"] == 2
    assert analyzer.validated_files == ["a.exe"]


def test_other_errors_count_as_failed_without_stopping(analyzer, tmp_path):
    _files(analyzer, tmp_path, ["a.exe", "b.exe"])
    _vt_returns(analyzer, {"a.exe": (None, False, "network"), "b.exe": _clean()})

    analyzer.analyze_directory(str(tmp_path))

    assert analyzer.last_scan_summary["failed"] == 1
    assert analyzer.last_scan_summary["clean"] == 1


def test_max_files_caps_the_scan_and_records_the_remainder(analyzer, tmp_path):
    analyzer.max_files = 2
    _files(analyzer, tmp_path, ["a.exe", "b.exe", "c.exe", "d.exe"])
    _vt_returns(analyzer, {n: _clean() for n in ["a.exe", "b.exe", "c.exe", "d.exe"]})

    analyzer.analyze_directory(str(tmp_path))

    assert analyzer.last_scan_summary["total_found"] == 4
    assert analyzer.last_scan_summary["total_to_scan"] == 2
    assert analyzer.last_scan_summary["skipped_by_limit"] == 2
    assert analyzer.last_scan_summary["scanned"] == 2


def test_unknown_hash_without_upload_is_recorded_as_not_found(analyzer, tmp_path):
    analyzer.upload_files = False
    _files(analyzer, tmp_path, ["a.exe"])
    _vt_returns(analyzer, {"a.exe": NOT_FOUND})

    findings = analyzer.analyze_directory(str(tmp_path))

    assert findings == []
    assert analyzer.last_scan_summary["not_found"] == 1
    assert analyzer.validated_files == []


def test_upload_path_reports_malicious_verdict(analyzer, tmp_path):
    analyzer.upload_files = True
    _files(analyzer, tmp_path, ["a.exe"])
    _vt_returns(analyzer, {"a.exe": NOT_FOUND})
    analyzer._upload_and_scan = lambda p, h: {"malicious": 4, "total_engines": 70}

    findings = analyzer.analyze_directory(str(tmp_path))

    assert len(findings) == 1
    assert analyzer.last_scan_summary["malicious"] == 1


def test_upload_path_reports_clean_verdict(analyzer, tmp_path):
    analyzer.upload_files = True
    _files(analyzer, tmp_path, ["a.exe"])
    _vt_returns(analyzer, {"a.exe": NOT_FOUND})
    analyzer._upload_and_scan = lambda p, h: {"malicious": 0, "total_engines": 70}

    findings = analyzer.analyze_directory(str(tmp_path))

    assert findings == []
    assert analyzer.last_scan_summary["clean"] == 1
    assert analyzer.validated_files == ["a.exe"]


def test_failed_upload_counts_as_failed(analyzer, tmp_path):
    analyzer.upload_files = True
    _files(analyzer, tmp_path, ["a.exe"])
    _vt_returns(analyzer, {"a.exe": NOT_FOUND})
    analyzer._upload_and_scan = lambda p, h: None

    analyzer.analyze_directory(str(tmp_path))

    assert analyzer.last_scan_summary["failed"] == 1


def test_exception_on_one_file_does_not_abort_the_others(analyzer, tmp_path):
    _files(analyzer, tmp_path, ["a.exe", "b.exe"])

    def boom(file_hash):
        if file_hash == "hash-of-a.exe":
            raise OSError("unreadable")
        return _clean()

    analyzer._query_virustotal_cached = boom

    analyzer.analyze_directory(str(tmp_path))

    assert analyzer.last_scan_summary["failed"] == 1
    assert analyzer.last_scan_summary["clean"] == 1


def test_disabled_analyzer_scans_nothing(tmp_path):
    vt = VirusTotalAnalyzer(api_key=None, enabled=False)

    assert vt.analyze_directory(str(tmp_path)) == []


def test_no_scannable_files_yields_no_summary_churn(analyzer, tmp_path):
    _files(analyzer, tmp_path, ["a.txt"])
    analyzer._should_scan_file = lambda f: False

    assert analyzer.analyze_directory(str(tmp_path)) == []
