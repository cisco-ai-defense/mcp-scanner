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

"""Unit tests for the vulnerable packages analyzer."""

import json
import os
import subprocess
import tempfile

import pytest
from unittest.mock import patch, MagicMock

from mcpscanner.core.analyzers.vulnerable_packages_analyzer import VulnerablePackagesAnalyzer
from mcpscanner.core.analyzers.base import SecurityFinding


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

SAMPLE_VULN_JSON = json.dumps(
    {
        "dependencies": [
            {
                "name": "flask",
                "version": "0.5",
                "vulns": [
                    {
                        "id": "PYSEC-2019-179",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-2019-1010083", "GHSA-5wv5-4vpf-pj6m"],
                        "description": "Flask before 1.0 is affected by unexpected memory usage.",
                    },
                    {
                        "id": "PYSEC-2018-66",
                        "fix_versions": ["0.12.3"],
                        "aliases": ["CVE-2018-1000656"],
                        "description": "Improper Input Validation in flask.",
                    },
                ],
            },
            {
                "name": "jinja2",
                "version": "3.1.2",
                "vulns": [],
            },
        ],
        "fixes": [],
    }
)

SAMPLE_CLEAN_JSON = json.dumps(
    {
        "dependencies": [
            {"name": "requests", "version": "2.31.0", "vulns": []},
            {"name": "urllib3", "version": "2.1.0", "vulns": []},
        ],
        "fixes": [],
    }
)

SAMPLE_NO_FIX_JSON = json.dumps(
    {
        "dependencies": [
            {
                "name": "somepkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2099-99999",
                        "fix_versions": [],
                        "aliases": [],
                        "description": "A vulnerability with no fix available yet.",
                    }
                ],
            }
        ],
        "fixes": [],
    }
)

SAMPLE_MULTI_PKG_JSON = json.dumps(
    {
        "dependencies": [
            {
                "name": "pkg-a",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "CVE-2024-0001",
                        "fix_versions": ["1.1"],
                        "aliases": ["GHSA-aaaa-bbbb-cccc"],
                        "description": "Vuln in pkg-a.",
                    }
                ],
            },
            {
                "name": "pkg-b",
                "version": "2.0",
                "vulns": [
                    {
                        "id": "CVE-2024-0002",
                        "fix_versions": ["2.1"],
                        "aliases": [],
                        "description": "Vuln in pkg-b.",
                    },
                    {
                        "id": "CVE-2024-0003",
                        "fix_versions": ["2.2"],
                        "aliases": ["GHSA-dddd-eeee-ffff"],
                        "description": "Another vuln in pkg-b.",
                    },
                ],
            },
            {"name": "pkg-c", "version": "3.0", "vulns": []},
        ],
        "fixes": [],
    }
)


def _make_completed_process(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["pip-audit"], returncode=returncode, stdout=stdout, stderr=stderr
    )


@pytest.fixture
def analyzer():
    """Create a VulnerablePackagesAnalyzer with the binary lookup mocked."""
    with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/usr/bin/pip-audit"]):
        return VulnerablePackagesAnalyzer(enabled=True)


@pytest.fixture
def disabled_analyzer():
    with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/usr/bin/pip-audit"]):
        return VulnerablePackagesAnalyzer(enabled=False)


@pytest.fixture
def tmp_requirements(tmp_path):
    """Create a temporary requirements file."""
    req = tmp_path / "requirements.txt"
    req.write_text("flask==0.5\njinja2==2.10\n")
    return str(req)


@pytest.fixture
def tmp_project_dir(tmp_path):
    """Create a temporary project directory with a requirements.txt."""
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    return str(tmp_path)


@pytest.fixture
def tmp_pyproject_dir(tmp_path):
    """Create a temporary project directory with pyproject.toml and .venv."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "test"\n')
    venv = tmp_path / ".venv"
    venv.mkdir()
    return str(tmp_path)


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------


class TestVulnerablePackagesAnalyzerInit:
    def test_init_defaults(self, analyzer):
        assert analyzer.enabled is True
        assert analyzer.vulnerability_service == "pypi"
        assert analyzer.timeout == 120
        assert analyzer.fix_mode is False
        assert analyzer.desc is True
        assert analyzer._pip_audit_cmd == ["/usr/bin/pip-audit"]
        assert analyzer.last_scan_summary is None

    def test_init_custom_params(self):
        with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/bin/pip-audit"]):
            a = VulnerablePackagesAnalyzer(
                enabled=True,
                vulnerability_service="osv",
                timeout=60,
                fix_mode=True,
                desc=False,
            )
        assert a.vulnerability_service == "osv"
        assert a.timeout == 60
        assert a.fix_mode is True
        assert a.desc is False

    def test_init_disabled(self, disabled_analyzer):
        assert disabled_analyzer.enabled is False

    def test_find_pip_audit_in_venv(self):
        with patch("mcpscanner.core.analyzers.vulnerable_packages_analyzer.Path") as MockPath:
            mock_venv_bin = MagicMock()
            mock_venv_bin.is_file.return_value = True
            mock_venv_bin.__str__ = lambda self: "/some/venv/bin/pip-audit"
            MockPath.return_value.parent.__truediv__ = MagicMock(return_value=mock_venv_bin)
            a = VulnerablePackagesAnalyzer.__new__(VulnerablePackagesAnalyzer)
            result = a._find_pip_audit()
            assert result == ["/some/venv/bin/pip-audit"]

    def test_find_pip_audit_via_which(self):
        with patch("mcpscanner.core.analyzers.vulnerable_packages_analyzer.Path") as MockPath:
            mock_venv_bin = MagicMock()
            mock_venv_bin.is_file.return_value = False
            MockPath.return_value.parent.__truediv__ = MagicMock(return_value=mock_venv_bin)
            with patch("shutil.which", side_effect=lambda x: "/usr/local/bin/pip-audit" if x == "pip-audit" else None):
                a = VulnerablePackagesAnalyzer.__new__(VulnerablePackagesAnalyzer)
                result = a._find_pip_audit()
                assert result == ["/usr/local/bin/pip-audit"]

    def test_find_pip_audit_via_uvx(self):
        with patch("mcpscanner.core.analyzers.vulnerable_packages_analyzer.Path") as MockPath:
            mock_venv_bin = MagicMock()
            mock_venv_bin.is_file.return_value = False
            MockPath.return_value.parent.__truediv__ = MagicMock(return_value=mock_venv_bin)
            def which_side_effect(name):
                if name == "uvx":
                    return "/usr/local/bin/uvx"
                return None
            with patch("shutil.which", side_effect=which_side_effect):
                a = VulnerablePackagesAnalyzer.__new__(VulnerablePackagesAnalyzer)
                result = a._find_pip_audit()
                assert result == ["/usr/local/bin/uvx", "pip-audit"]

    def test_find_pip_audit_via_uv_tool_run(self):
        with patch("mcpscanner.core.analyzers.vulnerable_packages_analyzer.Path") as MockPath:
            mock_venv_bin = MagicMock()
            mock_venv_bin.is_file.return_value = False
            MockPath.return_value.parent.__truediv__ = MagicMock(return_value=mock_venv_bin)
            def which_side_effect(name):
                if name == "uv":
                    return "/usr/local/bin/uv"
                return None
            with patch("shutil.which", side_effect=which_side_effect):
                a = VulnerablePackagesAnalyzer.__new__(VulnerablePackagesAnalyzer)
                result = a._find_pip_audit()
                assert result == ["/usr/local/bin/uv", "tool", "run", "pip-audit"]

    def test_find_pip_audit_not_found(self):
        with patch("mcpscanner.core.analyzers.vulnerable_packages_analyzer.Path") as MockPath:
            mock_venv_bin = MagicMock()
            mock_venv_bin.is_file.return_value = False
            MockPath.return_value.parent.__truediv__ = MagicMock(return_value=mock_venv_bin)
            with patch("shutil.which", return_value=None):
                a = VulnerablePackagesAnalyzer.__new__(VulnerablePackagesAnalyzer)
                result = a._find_pip_audit()
                assert result is None

    def test_find_prefers_venv_over_uvx(self):
        """Venv binary takes priority even when uvx is available."""
        with patch("mcpscanner.core.analyzers.vulnerable_packages_analyzer.Path") as MockPath:
            mock_venv_bin = MagicMock()
            mock_venv_bin.is_file.return_value = True
            mock_venv_bin.__str__ = lambda self: "/proj/.venv/bin/pip-audit"
            MockPath.return_value.parent.__truediv__ = MagicMock(return_value=mock_venv_bin)
            with patch("shutil.which", return_value="/usr/local/bin/uvx"):
                a = VulnerablePackagesAnalyzer.__new__(VulnerablePackagesAnalyzer)
                result = a._find_pip_audit()
                assert result == ["/proj/.venv/bin/pip-audit"]


# ---------------------------------------------------------------------------
# Disabled analyzer returns empty
# ---------------------------------------------------------------------------


class TestDisabledAnalyzer:
    def test_analyze_requirements_disabled(self, disabled_analyzer, tmp_requirements):
        assert disabled_analyzer.analyze_requirements(tmp_requirements) == []

    def test_analyze_path_disabled(self, disabled_analyzer, tmp_project_dir):
        assert disabled_analyzer.analyze_path(tmp_project_dir) == []


# ---------------------------------------------------------------------------
# analyze_requirements tests
# ---------------------------------------------------------------------------


class TestAnalyzeRequirements:
    @patch("subprocess.run")
    def test_returns_findings_for_vulnerable_deps(self, mock_run, analyzer, tmp_requirements):
        mock_run.return_value = _make_completed_process(
            stdout=SAMPLE_VULN_JSON, returncode=1
        )
        findings = analyzer.analyze_requirements(tmp_requirements)
        assert len(findings) == 2
        assert all(isinstance(f, SecurityFinding) for f in findings)

    @patch("subprocess.run")
    def test_returns_empty_for_clean_deps(self, mock_run, analyzer, tmp_requirements):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        findings = analyzer.analyze_requirements(tmp_requirements)
        assert findings == []

    def test_returns_empty_for_nonexistent_file(self, analyzer):
        findings = analyzer.analyze_requirements("/does/not/exist.txt")
        assert findings == []

    @patch("subprocess.run")
    def test_passes_correct_cli_args_default(self, mock_run, analyzer, tmp_requirements):
        """By default --no-deps and --disable-pip are NOT passed."""
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        analyzer.analyze_requirements(tmp_requirements)
        cmd = mock_run.call_args[0][0]
        assert "--format" in cmd
        assert "json" in cmd
        assert "-r" in cmd
        assert tmp_requirements in cmd
        assert "--no-deps" not in cmd
        assert "--disable-pip" not in cmd
        assert "--desc" in cmd

    @patch("subprocess.run")
    def test_skip_deps_and_disable_pip_opt_in(self, mock_run, tmp_requirements):
        """--no-deps and --disable-pip only appear when explicitly opted in."""
        with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/usr/bin/pip-audit"]):
            a = VulnerablePackagesAnalyzer(enabled=True, skip_deps=True, disable_pip=True)
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        a.analyze_requirements(tmp_requirements)
        cmd = mock_run.call_args[0][0]
        assert "--no-deps" in cmd
        assert "--disable-pip" in cmd


# ---------------------------------------------------------------------------
# analyze_path tests (routing logic)
# ---------------------------------------------------------------------------


class TestAnalyzePath:
    @patch("subprocess.run")
    def test_txt_file_routes_to_requirements(self, mock_run, analyzer, tmp_requirements):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        analyzer.analyze_path(tmp_requirements)
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd

    @patch("subprocess.run")
    def test_in_file_routes_to_requirements(self, mock_run, analyzer, tmp_path):
        req = tmp_path / "constraints.in"
        req.write_text("flask==0.5\n")
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        analyzer.analyze_path(str(req))
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd

    @patch("subprocess.run")
    def test_dir_with_requirements_txt(self, mock_run, analyzer, tmp_project_dir):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        analyzer.analyze_path(tmp_project_dir)
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd

    @patch("subprocess.run")
    def test_dir_with_pyproject_and_venv(self, mock_run, analyzer, tmp_pyproject_dir):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        analyzer.analyze_path(tmp_pyproject_dir)
        cmd = mock_run.call_args[0][0]
        assert "--path" in cmd
        venv_path = os.path.join(tmp_pyproject_dir, ".venv")
        assert venv_path in cmd

    @patch("subprocess.run")
    def test_dir_with_pyproject_no_venv(self, mock_run, analyzer, tmp_path):
        """Without .venv, pip-audit receives the project dir as a positional arg."""
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        analyzer.analyze_path(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "--path" not in cmd
        assert str(tmp_path) in cmd

    @patch("subprocess.run")
    def test_bare_dir_uses_path_flag(self, mock_run, analyzer, tmp_path):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        analyzer.analyze_path(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "--path" in cmd

    def test_nonexistent_path_returns_empty(self, analyzer):
        findings = analyzer.analyze_path("/nonexistent/dir")
        assert findings == []


# ---------------------------------------------------------------------------
# _run_and_parse edge cases
# ---------------------------------------------------------------------------


class TestRunAndParse:
    def test_no_binary_returns_empty(self):
        with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=None):
            a = VulnerablePackagesAnalyzer(enabled=True)
        findings = a._run_and_parse([], source="test")
        assert findings == []

    @patch("subprocess.run")
    def test_uvx_command_structure(self, mock_run):
        with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/usr/local/bin/uvx", "pip-audit"]):
            a = VulnerablePackagesAnalyzer(enabled=True)
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        a._run_and_parse([], source="test")
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/local/bin/uvx"
        assert cmd[1] == "pip-audit"
        assert "--format" in cmd
        assert "json" in cmd

    @patch("subprocess.run")
    def test_uv_tool_run_command_structure(self, mock_run):
        with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/usr/local/bin/uv", "tool", "run", "pip-audit"]):
            a = VulnerablePackagesAnalyzer(enabled=True)
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        a._run_and_parse([], source="test")
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/local/bin/uv"
        assert cmd[1] == "tool"
        assert cmd[2] == "run"
        assert cmd[3] == "pip-audit"
        assert "--format" in cmd

    @patch("subprocess.run")
    def test_timeout_returns_empty(self, mock_run, analyzer):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="pip-audit", timeout=120)
        findings = analyzer._run_and_parse(["-r", "req.txt"], source="req.txt")
        assert findings == []

    @patch("subprocess.run")
    def test_file_not_found_returns_empty(self, mock_run, analyzer):
        mock_run.side_effect = FileNotFoundError("pip-audit not found")
        findings = analyzer._run_and_parse(["-r", "req.txt"], source="req.txt")
        assert findings == []

    @patch("subprocess.run")
    def test_empty_stdout_returns_empty(self, mock_run, analyzer):
        mock_run.return_value = _make_completed_process(stdout="", returncode=0)
        findings = analyzer._run_and_parse([], source="test")
        assert findings == []

    @patch("subprocess.run")
    def test_empty_stdout_nonzero_exit_returns_empty(self, mock_run, analyzer):
        mock_run.return_value = _make_completed_process(stdout="", returncode=2)
        findings = analyzer._run_and_parse([], source="test")
        assert findings == []

    @patch("subprocess.run")
    def test_nonzero_exit_surfaces_stderr_warning(self, mock_run, analyzer, caplog):
        stderr_msg = (
            "Traceback (most recent call last):\n"
            "  File \"/tmp/venv/bin/pip-audit\", line 10\n"
            "subprocess.CalledProcessError: ensurepip failed with SIGABRT"
        )
        mock_run.return_value = _make_completed_process(
            stdout="", returncode=1, stderr=stderr_msg
        )
        import logging
        with caplog.at_level(logging.WARNING):
            findings = analyzer._run_and_parse([], source="test")
        assert findings == []
        assert "pip-audit exited with code 1" in caplog.text
        assert "ensurepip failed with SIGABRT" in caplog.text
        assert "--no-deps --disable-pip" in caplog.text

    @patch("subprocess.run")
    def test_nonzero_exit_no_resolution_hint_for_other_errors(self, mock_run, analyzer, caplog):
        mock_run.return_value = _make_completed_process(
            stdout="", returncode=1, stderr="ERROR: unknown option --bad-flag"
        )
        import logging
        with caplog.at_level(logging.WARNING):
            findings = analyzer._run_and_parse([], source="test")
        assert findings == []
        assert "pip-audit exited with code 1" in caplog.text
        assert "unknown option --bad-flag" in caplog.text
        assert "--no-deps --disable-pip" not in caplog.text

    @patch("subprocess.run")
    def test_invalid_json_returns_empty(self, mock_run, analyzer):
        mock_run.return_value = _make_completed_process(stdout="NOT JSON {{{")
        findings = analyzer._run_and_parse([], source="test")
        assert findings == []

    @patch("subprocess.run")
    def test_fix_mode_flag(self, mock_run):
        with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/bin/pip-audit"]):
            a = VulnerablePackagesAnalyzer(enabled=True, fix_mode=True)
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        a._run_and_parse([], source="test")
        cmd = mock_run.call_args[0][0]
        assert "--fix" in cmd

    @patch("subprocess.run")
    def test_desc_disabled(self, mock_run):
        with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/bin/pip-audit"]):
            a = VulnerablePackagesAnalyzer(enabled=True, desc=False)
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        a._run_and_parse([], source="test")
        cmd = mock_run.call_args[0][0]
        assert "--desc" not in cmd

    @patch("subprocess.run")
    def test_osv_service(self, mock_run):
        with patch.object(VulnerablePackagesAnalyzer, "_find_pip_audit", return_value=["/bin/pip-audit"]):
            a = VulnerablePackagesAnalyzer(enabled=True, vulnerability_service="osv")
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        a._run_and_parse([], source="test")
        cmd = mock_run.call_args[0][0]
        idx = cmd.index("--vulnerability-service")
        assert cmd[idx + 1] == "osv"


# ---------------------------------------------------------------------------
# _parse_results tests
# ---------------------------------------------------------------------------


class TestParseResults:
    def test_vulnerable_deps_parsed(self, analyzer):
        data = json.loads(SAMPLE_VULN_JSON)
        findings = analyzer._parse_results(data, source="req.txt")
        assert len(findings) == 2
        assert analyzer.last_scan_summary["total_packages"] == 2
        assert analyzer.last_scan_summary["vulnerable_packages"] == 1
        assert analyzer.last_scan_summary["total_vulnerabilities"] == 2
        assert analyzer.last_scan_summary["clean_packages"] == 1

    def test_clean_deps_parsed(self, analyzer):
        data = json.loads(SAMPLE_CLEAN_JSON)
        findings = analyzer._parse_results(data, source="req.txt")
        assert findings == []
        assert analyzer.last_scan_summary["total_packages"] == 2
        assert analyzer.last_scan_summary["vulnerable_packages"] == 0
        assert analyzer.last_scan_summary["total_vulnerabilities"] == 0

    def test_multi_package_multi_vuln(self, analyzer):
        data = json.loads(SAMPLE_MULTI_PKG_JSON)
        findings = analyzer._parse_results(data, source="req.txt")
        assert len(findings) == 3
        assert analyzer.last_scan_summary["total_packages"] == 3
        assert analyzer.last_scan_summary["vulnerable_packages"] == 2
        assert analyzer.last_scan_summary["total_vulnerabilities"] == 3
        assert analyzer.last_scan_summary["clean_packages"] == 1

    def test_empty_dependencies(self, analyzer):
        data = {"dependencies": [], "fixes": []}
        findings = analyzer._parse_results(data, source="req.txt")
        assert findings == []
        assert analyzer.last_scan_summary["total_packages"] == 0


# ---------------------------------------------------------------------------
# _create_finding tests
# ---------------------------------------------------------------------------


class TestCreateFinding:
    def test_finding_with_fix(self, analyzer):
        vuln = {
            "id": "PYSEC-2019-179",
            "fix_versions": ["1.0"],
            "aliases": ["CVE-2019-1010083"],
            "description": "Denial of service via crafted JSON.",
        }
        finding = analyzer._create_finding("flask", "0.5", vuln, "req.txt")

        assert isinstance(finding, SecurityFinding)
        assert finding.severity == "HIGH"
        assert finding.analyzer == "VULNERABLE_PACKAGES"
        assert finding.threat_category == "VULNERABLE DEPENDENCY"
        assert "flask==0.5" in finding.summary
        assert "PYSEC-2019-179" in finding.summary
        assert "CVE-2019-1010083" in finding.summary
        assert "Fix: 1.0" in finding.summary
        assert "Denial of service via crafted JSON." in finding.summary

    def test_finding_without_fix(self, analyzer):
        vuln = {
            "id": "CVE-2099-99999",
            "fix_versions": [],
            "aliases": [],
            "description": "No fix available yet.",
        }
        finding = analyzer._create_finding("somepkg", "1.0.0", vuln, "req.txt")

        assert finding.severity == "MEDIUM"
        assert "No fix available" in finding.summary
        assert "Aliases: None" in finding.summary

    def test_finding_details_structure(self, analyzer):
        vuln = {
            "id": "PYSEC-2019-179",
            "fix_versions": ["1.0"],
            "aliases": ["CVE-2019-1010083", "GHSA-5wv5-4vpf-pj6m"],
            "description": "A test vulnerability.",
        }
        finding = analyzer._create_finding("flask", "0.5", vuln, "requirements.txt")
        d = finding.details

        assert d["package_name"] == "flask"
        assert d["installed_version"] == "0.5"
        assert d["vulnerability_id"] == "PYSEC-2019-179"
        assert d["fix_versions"] == ["1.0"]
        assert d["aliases"] == ["CVE-2019-1010083", "GHSA-5wv5-4vpf-pj6m"]
        assert d["description"] == "A test vulnerability."
        assert d["source"] == "requirements.txt"
        assert d["threat_type"] == "VULNERABLE_DEPENDENCY"
        assert d["confidence"] == 0.95
        assert "https://osv.dev/vulnerability/PYSEC-2019-179" in d["references"]
        assert "Upgrade flask to version 1.0." in d["remediation"]

    def test_finding_details_no_fix_remediation(self, analyzer):
        vuln = {
            "id": "CVE-2099-99999",
            "fix_versions": [],
            "aliases": [],
            "description": "",
        }
        finding = analyzer._create_finding("broken", "0.1", vuln, "src")
        assert "Monitor CVE-2099-99999" in finding.details["remediation"]

    def test_finding_taxonomy_fields(self, analyzer):
        vuln = {
            "id": "X",
            "fix_versions": ["2.0"],
            "aliases": [],
            "description": "d",
        }
        finding = analyzer._create_finding("p", "1", vuln, "s")
        d = finding.details

        assert d["aitech"] == "AITech-9.2"
        assert d["aitech_name"] == "Detection Evasion"
        assert d["aisubtech"] == "AISubtech-9.2.1"
        assert d["aisubtech_name"] == "Supply Chain Compromise"
        assert "taxonomy_description" in d

    def test_finding_with_empty_description(self, analyzer):
        vuln = {
            "id": "CVE-0000-0000",
            "fix_versions": ["1.0"],
            "aliases": [],
            "description": "",
        }
        finding = analyzer._create_finding("pkg", "0.1", vuln, "src")
        assert "Details:" not in finding.summary

    def test_finding_multiple_fix_versions(self, analyzer):
        vuln = {
            "id": "CVE-1234-5678",
            "fix_versions": ["2.2.5", "2.3.2"],
            "aliases": [],
            "description": "Test.",
        }
        finding = analyzer._create_finding("pkg", "2.0", vuln, "src")
        assert "Fix: 2.2.5, 2.3.2" in finding.summary

    def test_finding_multiple_aliases(self, analyzer):
        vuln = {
            "id": "PYSEC-2021-66",
            "fix_versions": ["2.11.3"],
            "aliases": ["CVE-2020-28493", "GHSA-g3rq-g295-4j3m", "SNYK-PYTHON-JINJA2-1012994"],
            "description": "ReDoS.",
        }
        finding = analyzer._create_finding("jinja2", "2.10", vuln, "src")
        assert "CVE-2020-28493" in finding.summary
        assert "GHSA-g3rq-g295-4j3m" in finding.summary
        assert "SNYK-PYTHON-JINJA2-1012994" in finding.summary


# ---------------------------------------------------------------------------
# scan_summary tracking
# ---------------------------------------------------------------------------


class TestErrorHintHelpers:
    """Tests for _extract_error_hint and _is_resolution_failure."""

    def test_extract_error_hint_returns_exception_line(self):
        stderr = (
            "Traceback (most recent call last):\n"
            "  File \"/tmp/venv/bin/pip-audit\", line 10\n"
            "ValueError: something broke"
        )
        hint = VulnerablePackagesAnalyzer._extract_error_hint(stderr)
        assert "ValueError: something broke" in hint

    def test_extract_error_hint_returns_last_line_for_non_traceback(self):
        stderr = "WARNING: pip is old\nERROR: could not resolve"
        hint = VulnerablePackagesAnalyzer._extract_error_hint(stderr)
        assert "could not resolve" in hint

    def test_extract_error_hint_empty_stderr(self):
        hint = VulnerablePackagesAnalyzer._extract_error_hint("")
        assert hint == ""

    def test_is_resolution_failure_ensurepip(self):
        assert VulnerablePackagesAnalyzer._is_resolution_failure("ensurepip crashed")

    def test_is_resolution_failure_sigabrt(self):
        assert VulnerablePackagesAnalyzer._is_resolution_failure("died with SIGABRT")

    def test_is_resolution_failure_no_matching(self):
        assert VulnerablePackagesAnalyzer._is_resolution_failure(
            "No matching distribution found for flask==99.0"
        )

    def test_is_resolution_failure_false_for_unrelated(self):
        assert not VulnerablePackagesAnalyzer._is_resolution_failure(
            "ERROR: unknown option --bad-flag"
        )


# ---------------------------------------------------------------------------


class TestScanSummary:
    @patch("subprocess.run")
    def test_summary_updated_after_scan(self, mock_run, analyzer, tmp_requirements):
        mock_run.return_value = _make_completed_process(
            stdout=SAMPLE_VULN_JSON, returncode=1
        )
        analyzer.analyze_requirements(tmp_requirements)
        s = analyzer.last_scan_summary
        assert s is not None
        assert s["total_packages"] == 2
        assert s["vulnerable_packages"] == 1
        assert s["total_vulnerabilities"] == 2
        assert s["clean_packages"] == 1
        assert s["source"] == tmp_requirements

    @patch("subprocess.run")
    def test_summary_clean_scan(self, mock_run, analyzer, tmp_requirements):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLEAN_JSON)
        analyzer.analyze_requirements(tmp_requirements)
        s = analyzer.last_scan_summary
        assert s["vulnerable_packages"] == 0
        assert s["total_vulnerabilities"] == 0


# ---------------------------------------------------------------------------
# Threat mapping integration
# ---------------------------------------------------------------------------


class TestThreatMapping:
    def test_vulnerable_packages_threat_mapping_exists(self):
        from mcpscanner.threats.threats import ThreatMapping

        info = ThreatMapping.get_threat_mapping("vulnerable_packages", "VULNERABLE_DEPENDENCY")
        assert info["scanner_category"] == "VULNERABLE DEPENDENCY"
        assert info["aitech"] == "AITech-9.2"
        assert info["aisubtech"] == "AISubtech-9.2.1"

    def test_vulnerable_packages_in_analyzer_map(self):
        from mcpscanner.threats.threats import ThreatMapping

        analyzer_map = {
            "llm": ThreatMapping.LLM_THREATS,
            "yara": ThreatMapping.YARA_THREATS,
            "ai_defense": ThreatMapping.AI_DEFENSE_THREATS,
            "behavioral": ThreatMapping.BEHAVIORAL_THREATS,
            "vulnerable_packages": ThreatMapping.VULNERABLE_PACKAGES_THREATS,
        }
        assert "vulnerable_packages" in analyzer_map
        assert "VULNERABLE_DEPENDENCY" in analyzer_map["vulnerable_packages"]

    def test_simplified_mapping_created(self):
        from mcpscanner.threats.threats import VULNERABLE_PACKAGES_THREAT_MAPPING

        assert "VULNERABLE_DEPENDENCY" in VULNERABLE_PACKAGES_THREAT_MAPPING
        entry = VULNERABLE_PACKAGES_THREAT_MAPPING["VULNERABLE_DEPENDENCY"]
        assert entry["threat_category"] == "VULNERABLE DEPENDENCY"
        assert entry["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# AnalyzerEnum registration
# ---------------------------------------------------------------------------


class TestAnalyzerEnum:
    def test_vulnerable_packages_in_enum(self):
        from mcpscanner.core.models import AnalyzerEnum

        assert hasattr(AnalyzerEnum, "VULNERABLE_PACKAGES")
        assert AnalyzerEnum.VULNERABLE_PACKAGES.value == "vulnerable_packages"

    def test_vulnerable_packages_in_base_analyzer_map(self):
        from mcpscanner.core.analyzers.base import SecurityFinding

        finding = SecurityFinding(
            severity="HIGH",
            summary="test",
            analyzer="VULNERABLE_PACKAGES",
            threat_category="VULNERABLE DEPENDENCY",
            details={"threat_type": "VULNERABLE_DEPENDENCY"},
        )
        taxonomy = finding._get_mcp_taxonomy()
        assert taxonomy is not None
        assert taxonomy["aitech"] == "AITech-9.2"
        assert taxonomy["aisubtech"] == "AISubtech-9.2.1"


# ---------------------------------------------------------------------------
# Module export
# ---------------------------------------------------------------------------


class TestModuleExport:
    def test_vulnerable_packages_analyzer_importable_from_package(self):
        from mcpscanner.core.analyzers import VulnerablePackagesAnalyzer

        assert VulnerablePackagesAnalyzer is not None


# ---------------------------------------------------------------------------
# ReportGenerator integration tests for vulnerable-packages output
# ---------------------------------------------------------------------------


class TestReportGeneratorIntegration:
    """Verify that ReportGenerator handles vulnerable-packages data
    correctly across all output formats (summary, detailed, table, stats).
    """

    @pytest.fixture
    def vuln_results_dict(self):
        return {
            "scan_target": "vulnerable-packages:/tmp/requirements.txt",
            "scan_results": [
                {
                    "package_name": "flask==0.5",
                    "vulnerability_description": "PYSEC-2019-179: flask==0.5",
                    "status": "completed",
                    "is_safe": False,
                    "findings": {
                        "vulnerable_packages_analyzer": {
                            "severity": "HIGH",
                            "threat_summary": "Vulnerable dependency: flask==0.5",
                            "threat_names": ["VULNERABLE DEPENDENCY"],
                            "total_findings": 1,
                            "mcp_taxonomies": [
                                {
                                    "aitech": "AITech-9.2",
                                    "aitech_name": "Detection Evasion",
                                    "aisubtech": "AISubtech-9.2.1",
                                    "aisubtech_name": "Supply Chain Compromise",
                                }
                            ],
                        }
                    },
                },
                {
                    "package_name": "requests==2.31.0",
                    "vulnerability_description": "No vulnerabilities",
                    "status": "completed",
                    "is_safe": True,
                    "findings": {
                        "vulnerable_packages_analyzer": {
                            "severity": "SAFE",
                            "threat_summary": "No known vulnerabilities found",
                            "threat_names": [],
                            "total_findings": 0,
                            "mcp_taxonomies": [],
                        }
                    },
                },
            ],
            "requested_analyzers": ["VULNERABLE_PACKAGES"],
        }

    def test_summary_shows_package_names(self, vuln_results_dict):
        from mcpscanner.core.report_generator import ReportGenerator
        from mcpscanner.core.models import OutputFormat

        rg = ReportGenerator(vuln_results_dict)
        out = rg.format_output(format_type=OutputFormat.SUMMARY)
        assert "flask==0.5" in out
        assert "Unsafe items: 1" in out

    def test_detailed_shows_analyzer_results(self, vuln_results_dict):
        from mcpscanner.core.report_generator import ReportGenerator
        from mcpscanner.core.models import OutputFormat

        rg = ReportGenerator(vuln_results_dict)
        out = rg.format_output(format_type=OutputFormat.DETAILED)
        assert "vulnerable_packages_analyzer" in out
        assert "flask==0.5" in out
        assert "Severity: HIGH" in out

    def test_table_has_vuln_pkgs_column(self, vuln_results_dict):
        from mcpscanner.core.report_generator import ReportGenerator
        from mcpscanner.core.models import OutputFormat

        rg = ReportGenerator(vuln_results_dict)
        out = rg.format_output(format_type=OutputFormat.TABLE)
        assert "VULN_PKGS" in out
        assert "flask==0.5" in out

    def test_stats_includes_vuln_packages_analyzer(self, vuln_results_dict):
        from mcpscanner.core.report_generator import ReportGenerator

        rg = ReportGenerator(vuln_results_dict)
        stats = rg.get_statistics()
        assert "vulnerable_packages_analyzer" in stats["analyzer_stats"]
        vp = stats["analyzer_stats"]["vulnerable_packages_analyzer"]
        assert vp["total"] == 2
        assert vp["with_findings"] == 1

    def test_scan_target_used_instead_of_server_url(self, vuln_results_dict):
        from mcpscanner.core.report_generator import ReportGenerator
        from mcpscanner.core.models import OutputFormat

        rg = ReportGenerator(vuln_results_dict)
        assert rg.server_url == "vulnerable-packages:/tmp/requirements.txt"
        out = rg.format_output(format_type=OutputFormat.SUMMARY)
        assert "requirements.txt" in out

    def test_requested_analyzer_keys_registered(self, vuln_results_dict):
        from mcpscanner.core.report_generator import ReportGenerator

        rg = ReportGenerator(vuln_results_dict)
        assert "vulnerable_packages_analyzer" in rg.requested_analyzer_keys
        assert rg.is_vuln_pkg_scan is True

    def test_by_severity_groups_correctly(self, vuln_results_dict):
        from mcpscanner.core.report_generator import ReportGenerator
        from mcpscanner.core.models import OutputFormat

        rg = ReportGenerator(vuln_results_dict)
        out = rg.format_output(format_type=OutputFormat.BY_SEVERITY)
        assert "HIGH SEVERITY" in out
        assert "flask==0.5" in out
