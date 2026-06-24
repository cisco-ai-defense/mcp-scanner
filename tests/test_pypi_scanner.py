# Copyright 2025 Cisco Systems, Inc. and its affiliates
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

"""Tests for PyPI Package Scanner (Docker-sandboxed)."""

import asyncio
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from mcpscanner.core.pypi_scanner import (
    DockerNotAvailableError,
    LLMNotConfiguredError,
    PyPIPackageScanner,
    PyPIScanError,
)


class TestCheckDocker:
    """Tests for Docker availability checks."""

    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_docker_available(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        scanner = PyPIPackageScanner()
        scanner.check_docker()
        mock_run.assert_called_once()

    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_docker_not_running(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stderr="Cannot connect to the Docker daemon"
        )
        scanner = PyPIPackageScanner()
        with pytest.raises(DockerNotAvailableError, match="not running"):
            scanner.check_docker()

    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_docker_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        scanner = PyPIPackageScanner()
        with pytest.raises(DockerNotAvailableError, match="not installed"):
            scanner.check_docker()

    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_docker_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=10)
        scanner = PyPIPackageScanner()
        with pytest.raises(DockerNotAvailableError, match="did not respond"):
            scanner.check_docker()


class TestImageManagement:
    """Tests for Docker image build and check."""

    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_image_exists(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        scanner = PyPIPackageScanner()
        assert scanner._image_exists() is True

    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_image_not_exists(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        scanner = PyPIPackageScanner()
        assert scanner._image_exists() is False

    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_build_image_skips_if_exists(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        scanner = PyPIPackageScanner()
        scanner.build_image()
        mock_run.assert_called_once_with(
            ["docker", "image", "inspect", "mcp-scanner-pypi:latest"],
            capture_output=True,
            text=True,
        )

    @patch("mcpscanner.core.pypi_scanner.resources")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_build_image_force(self, mock_run, mock_resources):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        scanner = PyPIPackageScanner()
        scanner.build_image(force=True)
        calls = mock_run.call_args_list
        assert any("build" in str(c) for c in calls)


class TestScanPackage:
    """Tests for the scan_package method."""

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_scan_success_safe(self, mock_run, mock_check, mock_build):
        scan_output = {
            "package": "flask",
            "version": "latest",
            "python_files_scanned": 42,
            "total_findings": 0,
            "behavioral_findings": 0,
            "is_safe": True,
            "findings": [],
        }
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(scan_output),
            stderr="",
        )

        scanner = PyPIPackageScanner()
        result = scanner.scan_package("flask")

        assert result["is_safe"] is True
        assert result["total_findings"] == 0
        assert result["package"] == "flask"

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_scan_success_unsafe(self, mock_run, mock_check, mock_build):
        scan_output = {
            "package": "evil-pkg",
            "version": "1.0.0",
            "python_files_scanned": 5,
            "total_findings": 1,
            "behavioral_findings": 1,
            "is_safe": False,
            "findings": [
                {
                    "analyzer": "behavioral",
                    "severity": "HIGH",
                    "threat_category": "DATA EXFILTRATION",
                    "summary": "Tool sends data to external server",
                    "details": {},
                },
            ],
        }
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(scan_output),
            stderr="",
        )

        scanner = PyPIPackageScanner()
        result = scanner.scan_package("evil-pkg", version="1.0.0")

        assert result["is_safe"] is False
        assert result["total_findings"] == 1
        assert len(result["findings"]) == 1

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_scan_with_version(self, mock_run, mock_check, mock_build):
        scan_output = {
            "package": "flask",
            "version": "2.0.0",
            "is_safe": True,
            "findings": [],
        }
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(scan_output),
            stderr="",
        )

        scanner = PyPIPackageScanner()
        result = scanner.scan_package("flask", version="2.0.0")

        call_args = mock_run.call_args[0][0]
        assert "--version" in call_args
        assert "2.0.0" in call_args

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_scan_timeout(self, mock_run, mock_check, mock_build):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=300)

        scanner = PyPIPackageScanner()
        with pytest.raises(PyPIScanError, match="timed out"):
            scanner.scan_package("slow-package")

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_scan_empty_output(self, mock_run, mock_check, mock_build):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Container failed",
        )

        scanner = PyPIPackageScanner()
        with pytest.raises(PyPIScanError, match="No output"):
            scanner.scan_package("broken-package")

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_scan_invalid_json(self, mock_run, mock_check, mock_build):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="not json at all",
            stderr="",
        )

        scanner = PyPIPackageScanner()
        with pytest.raises(PyPIScanError, match="Invalid JSON"):
            scanner.scan_package("bad-output-package")

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_scan_container_error(self, mock_run, mock_check, mock_build):
        error_output = {
            "package": "nonexistent-pkg",
            "error": "Failed to download nonexistent-pkg",
            "is_safe": None,
            "findings": [],
        }
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(error_output),
            stderr="",
        )

        scanner = PyPIPackageScanner()
        with pytest.raises(PyPIScanError, match="Failed to download"):
            scanner.scan_package("nonexistent-pkg")

    def test_docker_required_no_fallback(self):
        """Verify there is no local/no-docker fallback."""
        scanner = PyPIPackageScanner()
        assert not hasattr(scanner, "scan_local")
        assert not hasattr(scanner, "scan_without_docker")


class TestConfiguration:
    """Tests for scanner configuration."""

    def test_default_image_name(self):
        scanner = PyPIPackageScanner()
        assert scanner._image_name == "mcp-scanner-pypi"
        assert scanner._image_tag == "latest"
        assert scanner._full_image == "mcp-scanner-pypi:latest"

    def test_custom_image_name(self):
        scanner = PyPIPackageScanner(
            image_name="custom-scanner",
            image_tag="v2",
            timeout=600,
        )
        assert scanner._full_image == "custom-scanner:v2"
        assert scanner._timeout == 600

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_env_vars_passed_to_container(self, mock_run, mock_check, mock_build):
        scan_output = {"package": "test", "is_safe": True, "findings": []}
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(scan_output),
            stderr="",
        )

        with patch.dict("os.environ", {
            "MCP_SCANNER_LLM_API_KEY": "test-key-123",
            "MCP_SCANNER_LLM_MODEL": "gpt-4o",
        }):
            scanner = PyPIPackageScanner()
            scanner.scan_package("test")

        call_args = mock_run.call_args[0][0]
        assert "-e" in call_args
        env_idx = [i for i, a in enumerate(call_args) if a == "-e"]
        env_values = [call_args[i + 1] for i in env_idx]
        assert any("LLM_API_KEY=test-key-123" in v for v in env_values)
        assert any("LLM_MODEL=gpt-4o" in v for v in env_values)

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_container_uses_rm_flag(self, mock_run, mock_check, mock_build):
        scan_output = {"package": "test", "is_safe": True, "findings": []}
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(scan_output),
            stderr="",
        )

        scanner = PyPIPackageScanner()
        scanner.scan_package("test")

        call_args = mock_run.call_args[0][0]
        assert "--rm" in call_args
        assert "--network=bridge" in call_args


class TestErrorCodeSurfacing:
    """Container-side ``error_code`` must round-trip to typed
    exceptions on the host."""

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_llm_not_configured_code_raises_typed_exception(
        self, mock_run, _mock_check, _mock_build
    ):
        """When the container reports ``error_code=llm_not_configured``
        the host must raise ``LLMNotConfiguredError`` so CLI exit codes
        / SDK try/excepts can distinguish a config error from a generic
        scan failure (regression guard for L1)."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(
                {
                    "package": "demo",
                    "version": "latest",
                    "error": "LLM_API_KEY not provided to the container",
                    "error_code": "llm_not_configured",
                    "is_safe": None,
                    "scan_status": "error",
                    "findings": [],
                }
            ),
            stderr="",
        )
        scanner = PyPIPackageScanner()
        with pytest.raises(LLMNotConfiguredError, match="LLM_API_KEY"):
            scanner.scan_package("demo")

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_unknown_error_code_falls_back_to_PyPIScanError(
        self, mock_run, _mock_check, _mock_build
    ):
        """Containers missing the field, or emitting an unknown code,
        must still surface as ``PyPIScanError`` — never silently as a
        successful scan."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(
                {
                    "package": "demo",
                    "version": "latest",
                    "error": "tarball corrupt",
                    "is_safe": None,
                    "scan_status": "error",
                    "findings": [],
                }
            ),
            stderr="",
        )
        scanner = PyPIPackageScanner()
        with pytest.raises(PyPIScanError, match="tarball corrupt"):
            scanner.scan_package("demo")


class TestAsyncEntrypoint:
    """``scan_package_async`` is the SDK shape for callers already
    inside an event loop."""

    def test_sync_scan_in_async_context_raises_clear_error(self):
        """Calling the sync entrypoint from a running loop used to
        deadlock; now it raises a clear RuntimeError pointing the
        caller at ``scan_package_async`` (regression guard for P2).

        The check fires before any Docker/network I/O, so we use the
        local path to keep this test hermetic."""
        from mcpscanner.config.config import Config

        scanner = PyPIPackageScanner(
            use_docker=False,
            config=Config(llm_provider_api_key="test-key"),
        )

        async def _run():
            scanner.scan_package("demo")

        with pytest.raises(RuntimeError, match="scan_package_async"):
            asyncio.run(_run())

    @patch.object(PyPIPackageScanner, "build_image")
    @patch.object(PyPIPackageScanner, "check_docker")
    @patch("mcpscanner.core.pypi_scanner.subprocess.run")
    def test_async_scan_composes_with_existing_event_loop(
        self, mock_run, _mock_check, _mock_build
    ):
        """The async entrypoint must work from inside an active loop —
        the supported SDK shape for FastAPI/async batch jobs."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                {
                    "package": "demo",
                    "version": "1.0.0",
                    "findings": [],
                    "is_safe": True,
                    "total_findings": 0,
                }
            ),
            stderr="",
        )
        scanner = PyPIPackageScanner()

        async def _run():
            return await scanner.scan_package_async("demo")

        result = asyncio.run(_run())
        assert result["is_safe"] is True


class TestLocalFileCount:
    """The local PyPI scan must count the same files the analyzer scans."""

    def test_file_count_skips_hidden_dirs_like_analyzer(self, tmp_path):
        """Regression: local mode used ``rglob("*.py")`` which counted
        files in hidden dirs (e.g. ``.tox``/``.venv``) that the
        analyzer's ``_find_python_files`` explicitly skips — inflating
        ``python_files_scanned`` past what was actually analysed. We now
        use the shared ``count_source_files`` which skips hidden paths,
        matching both the analyzer and the Docker entrypoint."""
        from mcpscanner.core.package_sandbox import count_source_files

        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "mod.py").write_text("x = 1\n")
        hidden = tmp_path / ".tox" / "lib"
        hidden.mkdir(parents=True)
        (hidden / "vendored.py").write_text("y = 2\n")

        count = count_source_files(tmp_path, extensions=(".py",), skip_dirs=())

        # Only pkg/mod.py — the hidden .tox tree is ignored. A naive
        # rglob would have returned 2.
        assert count == 1

    def test_file_count_skips_pycache_and_node_modules(self, tmp_path):
        """The PyPI counter must mirror the analyzer's ``_find_source_files``
        exclusions so ``python_files_scanned`` never counts files under
        ``__pycache__``/``node_modules`` that the analyzer skips."""
        from mcpscanner.core.package_sandbox import count_source_files

        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "mod.py").write_text("x = 1\n")
        cache = tmp_path / "pkg" / "__pycache__"
        cache.mkdir()
        (cache / "stale.py").write_text("y = 2\n")
        vendored = tmp_path / "node_modules" / "dep"
        vendored.mkdir(parents=True)
        (vendored / "polyglot.py").write_text("z = 3\n")

        count = count_source_files(
            tmp_path,
            extensions=(".py",),
            skip_dirs=("__pycache__", "node_modules"),
        )
        assert count == 1


class _FakeConfig:
    """Minimal config stand-in for behavioural analyzer construction."""

    def __init__(self, llm_provider_api_key: str = "test-key"):
        self.llm_provider_api_key = llm_provider_api_key
        self.llm_model = "gpt-4o-mini"
        self.llm_base_url = ""
        self.llm_api_version = ""


def test_python_analyzer_extraction_crash_marks_scan_error(monkeypatch):
    """Regression: a wholesale context-extraction failure in the Python
    behavioural analyzer is swallowed by ``_analyze_source_code`` (it
    returns an empty findings list rather than re-raising). It must still
    bump ``analysis_errors`` so ``analysis_scan_status`` reports ``error``
    — otherwise a package whose sources crashed the extractor would be
    reported ``is_safe=True``."""
    from mcpscanner.core.analyzers.behavioral import code_analyzer as cmod
    from mcpscanner.core.pypi_scanner import analysis_scan_status

    # Keep construction offline; analysis_scan_status reads analysis_errors.
    monkeypatch.setattr(cmod, "AlignmentOrchestrator", MagicMock())

    class _Boom:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("extractor exploded")

    # Both the primary and fallback extractors blow up for this file.
    monkeypatch.setattr(cmod, "ContextExtractor", _Boom)
    monkeypatch.setattr(cmod, "NativeAnalyzer", _Boom)

    analyzer = cmod.BehavioralCodeAnalyzer(_FakeConfig())
    findings = asyncio.run(
        analyzer._analyze_source_code(
            "@mcp.tool()\ndef greet(name):\n    return name\n",
            {"file_path": "server.py"},
        )
    )

    assert findings == []
    assert analyzer.analysis_errors == 1
    assert analysis_scan_status(analyzer, findings) == "error"
