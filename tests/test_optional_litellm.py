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

"""YARA and other non-LLM analyzers must import when LiteLLM is absent."""

import builtins
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_without_litellm(code: str) -> subprocess.CompletedProcess[str]:
    """Run ``code`` in a fresh interpreter where ``litellm`` cannot import."""
    script = (
        "import sys\n"
        "sys.modules['litellm'] = None\n"
        f"{textwrap.dedent(code).strip()}\n"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _import_raising(monkeypatch, make_exc) -> None:
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "litellm" or name.startswith("litellm."):
            raise make_exc()
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_missing_litellm_package_is_the_extra(monkeypatch):
    from mcpscanner.utils.optional_litellm import (
        litellm_importable,
        require_acompletion,
    )

    saved = sys.modules.pop("litellm", None)
    _import_raising(
        monkeypatch,
        lambda: ModuleNotFoundError("No module named 'litellm'", name="litellm"),
    )
    try:
        assert litellm_importable() is False
        sys.modules.pop("litellm", None)
        with pytest.raises(ImportError, match="cisco-ai-mcp-scanner\\[llm\\]"):
            require_acompletion()
    finally:
        if saved is not None:
            sys.modules["litellm"] = saved


def test_litellm_dependency_error_is_not_a_missing_extra(monkeypatch):
    from mcpscanner.utils.optional_litellm import (
        litellm_importable,
        require_acompletion,
    )

    saved = sys.modules.pop("litellm", None)
    _import_raising(
        monkeypatch,
        lambda: ModuleNotFoundError("No module named 'httpx'", name="httpx"),
    )
    try:
        with pytest.raises(ModuleNotFoundError) as imported:
            litellm_importable()
        assert imported.value.name == "httpx"
        sys.modules.pop("litellm", None)
        with pytest.raises(ModuleNotFoundError) as required:
            require_acompletion()
        assert required.value.name == "httpx"
    finally:
        if saved is not None:
            sys.modules["litellm"] = saved


def test_cli_imports_when_litellm_is_missing():
    result = _run_without_litellm(
        """
        from mcpscanner.cli import cli_entry_point
        from mcpscanner.core.scanner import Scanner
        print("imported")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "imported" in result.stdout


def test_llm_analyzer_names_the_extra_when_litellm_is_missing():
    result = _run_without_litellm(
        """
        from mcpscanner import Config
        from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
        try:
            LLMAnalyzer(Config(llm_provider_api_key="test-key"))
        except ImportError as exc:
            text = str(exc)
            if "cisco-ai-mcp-scanner[llm]" not in text:
                raise SystemExit(text)
            print("missing-extra")
        else:
            raise SystemExit("LLMAnalyzer constructed without LiteLLM")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "missing-extra" in result.stdout


def test_alignment_client_names_the_extra_when_litellm_is_missing():
    result = _run_without_litellm(
        """
        from mcpscanner import Config
        from mcpscanner.core.analyzers.behavioral.alignment import (
            alignment_llm_client,
        )
        AlignmentLLMClient = alignment_llm_client.AlignmentLLMClient
        try:
            AlignmentLLMClient(Config(llm_provider_api_key="test-key"))
        except ImportError as exc:
            text = str(exc)
            if "cisco-ai-mcp-scanner[llm]" not in text:
                raise SystemExit(text)
            print("missing-extra")
        else:
            raise SystemExit("AlignmentLLMClient constructed without LiteLLM")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "missing-extra" in result.stdout


def test_scanner_reports_the_extra_when_llm_is_requested():
    result = _run_without_litellm(
        """
        from mcpscanner import Config
        from mcpscanner.core.models import AnalyzerEnum
        from mcpscanner.core.scanner import Scanner
        from mcpscanner.utils.optional_litellm import LiteLLMNotInstalledError
        scanner = Scanner(Config(llm_provider_api_key="test-key"))
        try:
            scanner._validate_analyzer_requirements([AnalyzerEnum.LLM])
        except LiteLLMNotInstalledError as exc:
            text = str(exc)
            if "cisco-ai-mcp-scanner[llm]" not in text:
                raise SystemExit(text)
            if not isinstance(exc, ValueError):
                raise SystemExit("typed error is not a ValueError")
            print("missing-extra")
        else:
            raise SystemExit("LLM request succeeded without LiteLLM")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "missing-extra" in result.stdout


def test_apply_meta_fails_when_litellm_is_missing():
    result = _run_without_litellm(
        """
        import asyncio
        from mcpscanner import Config
        from mcpscanner.core.models import AnalyzerEnum
        from mcpscanner.core.result import ToolScanResult
        from mcpscanner.core.scanner import Scanner
        scanner = Scanner.for_meta_only(Config(llm_provider_api_key="test-key"))
        original = [
            ToolScanResult(
                tool_name="echo",
                tool_description="echo text",
                status="completed",
                analyzers=["yara"],
                findings=[],
            )
        ]
        try:
            asyncio.run(
                scanner.apply_meta_to_results(original, [AnalyzerEnum.META])
            )
        except ValueError as exc:
            text = str(exc)
            if "cisco-ai-mcp-scanner[llm]" not in text:
                raise SystemExit(text)
            print("missing-extra")
        else:
            raise SystemExit("meta pass succeeded without LiteLLM")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "missing-extra" in result.stdout


def test_static_enable_meta_exits_when_litellm_is_missing(tmp_path):
    tools = tmp_path / "tools.json"
    tools.write_text(
        '{"tools":[{"name":"echo","description":"echo text",'
        '"inputSchema":{"type":"object"}}]}',
        encoding="utf-8",
    )
    result = _run_without_litellm(
        f"""
        import sys
        sys.argv = [
            "mcp-scanner",
            "--analyzers",
            "yara",
            "--enable-meta",
            "--llm-api-key",
            "test-key",
            "static",
            "--tools",
            {str(tools)!r},
        ]
        from mcpscanner.cli import cli_entry_point
        cli_entry_point()
        """
    )
    assert result.returncode != 0, result.stdout
    assert "cisco-ai-mcp-scanner[llm]" in result.stderr


def test_static_yara_continues_when_llm_is_unconfigured(tmp_path):
    tools = tmp_path / "tools.json"
    tools.write_text(
        '{"tools":[{"name":"echo","description":"echo text",'
        '"inputSchema":{"type":"object"}}]}',
        encoding="utf-8",
    )
    result = _run_without_litellm(
        f"""
        import os
        import sys
        from mcpscanner.cli import cli_entry_point
        os.environ.pop("MCP_SCANNER_LLM_API_KEY", None)
        os.environ["MCP_SCANNER_LLM_MODEL"] = "gpt-4o"
        sys.argv = [
            "mcp-scanner",
            "--analyzers",
            "yara,llm",
            "static",
            "--tools",
            {str(tools)!r},
        ]
        cli_entry_point()
        """
    )
    assert result.returncode == 0, result.stderr
    assert "cisco-ai-mcp-scanner[llm]" not in result.stderr


def test_omitted_meta_keeps_results_when_analyzer_is_unconfigured():
    import asyncio

    from mcpscanner import Config
    from mcpscanner.core.result import ToolScanResult
    from mcpscanner.core.scanner import Scanner

    scanner = Scanner.for_meta_only(Config(llm_model="gpt-4o"))
    original = [
        ToolScanResult(
            tool_name="echo",
            tool_description="echo text",
            status="completed",
            analyzers=["yara"],
            findings=[],
        )
    ]
    out = asyncio.run(scanner.apply_meta_to_results(original))
    assert out == original


def test_explicit_meta_helper_does_not_skip():
    import asyncio

    from mcpscanner import Config
    from mcpscanner.core.models import AnalyzerEnum
    from mcpscanner.core.result import ToolScanResult
    from mcpscanner.core.scanner import Scanner

    scanner = Scanner.for_meta_only(Config(llm_model="gpt-4o"))
    original = [
        ToolScanResult(
            tool_name="echo",
            tool_description="echo text",
            status="completed",
            analyzers=["yara"],
            findings=[],
        )
    ]
    try:
        asyncio.run(
            scanner._run_meta_analysis_on_results(original, [AnalyzerEnum.META])
        )
    except ValueError as exc:
        assert "Meta analyzer requested" in str(exc)
    else:
        raise AssertionError("meta helper returned results without an analyzer")


def test_readiness_judge_fails_when_litellm_is_missing():
    result = _run_without_litellm(
        """
        from mcpscanner.core.analyzers.readiness.readiness_analyzer import (
            ReadinessAnalyzer,
        )
        try:
            ReadinessAnalyzer(enable_llm_judge=True)
        except ImportError as exc:
            text = str(exc)
            if "cisco-ai-mcp-scanner[llm]" not in text:
                raise SystemExit(text)
            print("missing-extra")
        else:
            raise SystemExit("readiness judge started without LiteLLM")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "missing-extra" in result.stdout


def test_static_yara_continues_when_bedrock_has_no_api_key(tmp_path):
    tools = tmp_path / "tools.json"
    tools.write_text(
        '{"tools":[{"name":"echo","description":"echo text",'
        '"inputSchema":{"type":"object"}}]}',
        encoding="utf-8",
    )
    result = _run_without_litellm(
        f"""
        import os
        import sys
        from mcpscanner.cli import cli_entry_point
        os.environ.pop("MCP_SCANNER_LLM_API_KEY", None)
        os.environ["MCP_SCANNER_LLM_MODEL"] = "bedrock/us.anthropic.claude"
        sys.argv = [
            "mcp-scanner",
            "--analyzers",
            "yara,llm",
            "static",
            "--tools",
            {str(tools)!r},
        ]
        cli_entry_point()
        """
    )
    assert result.returncode == 0, result.stderr
    assert "cisco-ai-mcp-scanner[llm]" not in result.stderr
    assert "MCP_SCANNER_LLM_API_KEY not set" in result.stderr


def test_unconfigured_llm_does_not_ask_for_the_extra():
    result = _run_without_litellm(
        """
        from mcpscanner import Config
        from mcpscanner.core.models import AnalyzerEnum
        from mcpscanner.core.scanner import Scanner
        from mcpscanner.utils.optional_litellm import LiteLLMNotInstalledError
        scanner = Scanner(Config(llm_model="gpt-4o"))
        try:
            scanner._validate_analyzer_requirements([AnalyzerEnum.LLM])
        except LiteLLMNotInstalledError as exc:
            raise SystemExit("install error for an unconfigured analyzer: " + str(exc))
        except ValueError as exc:
            text = str(exc)
            if "cisco-ai-mcp-scanner[llm]" in text:
                raise SystemExit(text)
            if "MCP_SCANNER_LLM_API_KEY" not in text:
                raise SystemExit(text)
            print("missing-key")
        else:
            raise SystemExit("unconfigured LLM request succeeded")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "missing-key" in result.stdout


def test_bedrock_without_key_still_names_the_extra():
    result = _run_without_litellm(
        """
        from mcpscanner import Config
        from mcpscanner.core.models import AnalyzerEnum
        from mcpscanner.core.scanner import Scanner
        scanner = Scanner(Config(llm_model="bedrock/us.anthropic.claude"))
        try:
            scanner._validate_analyzer_requirements([AnalyzerEnum.LLM])
        except ValueError as exc:
            text = str(exc)
            if "cisco-ai-mcp-scanner[llm]" not in text:
                raise SystemExit(text)
            print("missing-extra")
        else:
            raise SystemExit("bedrock request succeeded without LiteLLM")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "missing-extra" in result.stdout


def test_remote_unconfigured_llm_does_not_ask_for_the_extra():
    result = _run_without_litellm(
        """
        import os
        import sys
        from mcpscanner.cli import cli_entry_point
        os.environ.pop("MCP_SCANNER_LLM_API_KEY", None)
        os.environ["MCP_SCANNER_LLM_MODEL"] = "gpt-4o"
        sys.argv = [
            "mcp-scanner",
            "--analyzers",
            "yara,llm",
            "remote",
            "--server-url",
            "http://127.0.0.1:9/mcp",
        ]
        cli_entry_point()
        """
    )
    assert result.returncode != 0, result.stdout
    assert "cisco-ai-mcp-scanner[llm]" not in result.stderr
    assert "MCP_SCANNER_LLM_API_KEY" in result.stderr


def test_remote_scan_exits_when_litellm_is_missing():
    result = _run_without_litellm(
        """
        import os
        import sys
        from mcpscanner.cli import cli_entry_point
        os.environ.pop("MCP_SCANNER_LLM_API_KEY", None)
        os.environ["MCP_SCANNER_LLM_MODEL"] = "gpt-4o"
        sys.argv = [
            "mcp-scanner",
            "--analyzers",
            "llm",
            "--llm-api-key",
            "test-key",
            "remote",
            "--server-url",
            "http://127.0.0.1:9/mcp",
        ]
        cli_entry_point()
        """
    )
    assert result.returncode != 0, result.stdout
    assert "LiteLLM is required for the LLM analyzer" in result.stderr


def test_behavioral_dockerfiles_install_the_llm_extra():
    docker_dir = REPO_ROOT / "mcpscanner" / "docker"
    names = (
        "Dockerfile",
        "Dockerfile.npm",
        "Dockerfile.wheel",
        "Dockerfile.npm.wheel",
    )
    for name in names:
        text = (docker_dir / name).read_text(encoding="utf-8")
        install_lines = [line for line in text.splitlines() if "pip install" in line]
        assert install_lines, name
        assert all("[llm]" in line for line in install_lines), (name, install_lines)


def test_api_maps_missing_litellm_to_400():
    from mcpscanner.api.router import _http_exception_for_scan_failure
    from mcpscanner.utils.optional_litellm import LiteLLMNotInstalledError

    missing = _http_exception_for_scan_failure(
        LiteLLMNotInstalledError("LLM analyzer is unavailable")
    )
    assert missing.status_code == 400
    # A reworded message still maps by type. Mentioning the extra in an
    # unrelated ValueError must stay a 404.
    decoy = _http_exception_for_scan_failure(
        ValueError("See cisco-ai-mcp-scanner[llm] in the docs")
    )
    assert decoy.status_code == 404
    not_found = _http_exception_for_scan_failure(ValueError("Tool 'echo' not found"))
    assert not_found.status_code == 404
