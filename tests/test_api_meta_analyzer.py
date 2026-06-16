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

"""API parity tests for the LLM Meta-Analyzer.

These tests pin three contracts:

1. ``APIScanRequest.enable_meta`` is the HTTP equivalent of the CLI
   ``--enable-meta`` flag. When True, ``AnalyzerEnum.META`` must be appended
   to the resolved analyzer list (without duplicating an explicit ``meta``
   entry). When False or omitted, META must NOT be added.
2. Every scan endpoint (``/scan-tool``, ``/scan-all-tools``, ``/scan-prompt``,
   ``/scan-all-prompts``, ``/scan-resource``, ``/scan-all-resources``,
   ``/scan-instructions``) must thread the resolved analyzer list to BOTH
   the ``ScannerFactory`` (so the right analyzer instances are constructed)
   AND the underlying ``Scanner.scan_remote_server_*`` call (so meta-analysis
   actually runs). Forgetting either of these two sites was the silent-drop
   defect that motivated this test suite.
3. ``mcpscanner.api.api._prepare_scanner_config`` keeps LLM credentials wired
   when ANY LLM-backed analyzer is requested (LLM, BEHAVIORAL, or META) — not
   just when ``LLM`` is explicitly in the analyzer list. The original code
   blanked the LLM API key for non-LLM scans, which made
   ``analyzers=["yara","meta"]`` 404 with a confusing "MCP_SCANNER_LLM_API_KEY
   not configured" error even when the env was correct.
"""

from __future__ import annotations

from typing import Any, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcpscanner.api.router import get_scanner, router
from mcpscanner.core.models import (
    AnalyzerEnum,
    APIScanRequest,
    SpecificInstructionsScanRequest,
    SpecificPromptScanRequest,
    SpecificResourceScanRequest,
    SpecificToolScanRequest,
)
from mcpscanner.core.result import (
    InstructionsScanResult,
    PromptScanResult,
    ResourceScanResult,
    ToolScanResult,
)


# ---------------------------------------------------------------------------
# APIScanRequest.resolved_analyzers — model-level contract
# ---------------------------------------------------------------------------


class TestResolvedAnalyzers:
    """``APIScanRequest.resolved_analyzers`` mirrors CLI ``--enable-meta``."""

    def test_default_does_not_include_meta(self):
        """No ``enable_meta`` flag → META is not auto-appended."""
        req = APIScanRequest(server_url="https://example.com/mcp")
        assert AnalyzerEnum.META not in req.resolved_analyzers()

    def test_enable_meta_false_does_not_include_meta(self):
        """``enable_meta=False`` → META is not auto-appended."""
        req = APIScanRequest(
            server_url="https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
            enable_meta=False,
        )
        assert req.resolved_analyzers() == [AnalyzerEnum.YARA]

    def test_enable_meta_true_appends_meta(self):
        """``enable_meta=True`` → META is appended once."""
        req = APIScanRequest(
            server_url="https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA, AnalyzerEnum.LLM],
            enable_meta=True,
        )
        resolved = req.resolved_analyzers()
        assert resolved == [AnalyzerEnum.YARA, AnalyzerEnum.LLM, AnalyzerEnum.META]

    def test_enable_meta_with_explicit_meta_does_not_duplicate(self):
        """If META is already in ``analyzers``, ``enable_meta=True`` is a no-op."""
        req = APIScanRequest(
            server_url="https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA, AnalyzerEnum.META],
            enable_meta=True,
        )
        resolved = req.resolved_analyzers()
        assert resolved.count(AnalyzerEnum.META) == 1
        assert resolved == [AnalyzerEnum.YARA, AnalyzerEnum.META]

    def test_explicit_meta_without_enable_meta_is_honoured(self):
        """An explicit ``meta`` entry runs meta-analysis even with ``enable_meta=False``."""
        req = APIScanRequest(
            server_url="https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA, AnalyzerEnum.META],
            enable_meta=False,
        )
        assert AnalyzerEnum.META in req.resolved_analyzers()

    def test_resolved_does_not_mutate_request_analyzers(self):
        """``resolved_analyzers`` returns a new list; the request is unchanged."""
        original = [AnalyzerEnum.YARA]
        req = APIScanRequest(
            server_url="https://example.com/mcp",
            analyzers=original,
            enable_meta=True,
        )
        resolved = req.resolved_analyzers()
        assert resolved == [AnalyzerEnum.YARA, AnalyzerEnum.META]
        assert req.analyzers == [AnalyzerEnum.YARA]
        assert resolved is not req.analyzers


# ---------------------------------------------------------------------------
# Endpoint-level parity — every scan endpoint threads META through both
# the ScannerFactory call and the Scanner.scan_remote_server_* call.
# ---------------------------------------------------------------------------


@pytest.fixture
def captured_factory_and_scanner():
    """Build a FastAPI app whose ``ScannerFactory`` records the analyzer list.

    The fixture returns a ``(captured, app)`` pair where ``captured`` is a
    plain dict that the test asserts against. Each endpoint is exercised
    against this app via ``TestClient``.
    """
    captured: dict[str, Any] = {
        "factory_analyzers": None,
        "scan_call_analyzers": None,
    }

    # --- mock Scanner instance ------------------------------------------
    scanner = MagicMock()
    scanner.get_custom_analyzers.return_value = []

    def _capture(method_name: str, return_value: Any):
        async def _impl(**kwargs: Any) -> Any:
            captured["scan_call_analyzers"] = list(kwargs.get("analyzers") or [])
            return return_value

        setattr(scanner, method_name, AsyncMock(side_effect=_impl))

    tool_result = ToolScanResult(
        tool_name="t",
        tool_description="",
        status="completed",
        analyzers=[],
        findings=[],
    )
    prompt_result = PromptScanResult(
        prompt_name="p",
        prompt_description="",
        status="completed",
        analyzers=[],
        findings=[],
    )
    resource_result = ResourceScanResult(
        resource_uri="res://x",
        resource_name="x",
        resource_mime_type="text/plain",
        status="completed",
        analyzers=[],
        findings=[],
    )
    instructions_result = InstructionsScanResult(
        instructions="",
        server_name="s",
        protocol_version="2025-06-18",
        status="completed",
        analyzers=[],
        findings=[],
    )

    _capture("scan_remote_server_tool", tool_result)
    _capture("scan_remote_server_tools", [tool_result])
    _capture("scan_remote_server_prompt", prompt_result)
    _capture("scan_remote_server_prompts", [prompt_result])
    _capture("scan_remote_server_resource", resource_result)
    _capture("scan_remote_server_resources", [resource_result])
    _capture("scan_remote_server_instructions", instructions_result)

    # --- mock ScannerFactory --------------------------------------------
    def factory(analyzers: List[AnalyzerEnum]) -> Any:
        captured["factory_analyzers"] = list(analyzers)
        return scanner

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_scanner] = lambda: factory

    return captured, app


class TestEndpointAnalyzerThreading:
    """Each scan endpoint must thread resolved analyzers to BOTH sites."""

    @pytest.mark.parametrize(
        "endpoint, payload",
        [
            (
                "/scan-tool",
                {
                    "server_url": "https://example.com/mcp",
                    "tool_name": "demo",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-all-tools",
                {
                    "server_url": "https://example.com/mcp",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-prompt",
                {
                    "server_url": "https://example.com/mcp",
                    "prompt_name": "demo",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-all-prompts",
                {
                    "server_url": "https://example.com/mcp",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-resource",
                {
                    "server_url": "https://example.com/mcp",
                    "resource_uri": "res://x",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-all-resources",
                {
                    "server_url": "https://example.com/mcp",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-instructions",
                {
                    "server_url": "https://example.com/mcp",
                    "analyzers": ["yara"],
                },
            ),
        ],
    )
    def test_enable_meta_true_threads_meta_to_both_sites(
        self, captured_factory_and_scanner, endpoint, payload
    ):
        """Setting ``enable_meta=True`` must add META to the factory AND scan call."""
        captured, app = captured_factory_and_scanner
        client = TestClient(app)

        body = {**payload, "enable_meta": True}
        response = client.post(endpoint, json=body)

        assert response.status_code == 200, response.text
        assert captured["factory_analyzers"] == [AnalyzerEnum.YARA, AnalyzerEnum.META], (
            "ScannerFactory did not receive META — meta analyzer would never "
            "be initialised for endpoint %s" % endpoint
        )
        assert captured["scan_call_analyzers"] == [
            AnalyzerEnum.YARA,
            AnalyzerEnum.META,
        ], (
            "Scanner.scan_remote_server_* did not receive META — "
            "meta-analysis pass would be skipped for endpoint %s" % endpoint
        )

    @pytest.mark.parametrize(
        "endpoint, payload",
        [
            (
                "/scan-tool",
                {
                    "server_url": "https://example.com/mcp",
                    "tool_name": "demo",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-all-tools",
                {"server_url": "https://example.com/mcp", "analyzers": ["yara"]},
            ),
            (
                "/scan-prompt",
                {
                    "server_url": "https://example.com/mcp",
                    "prompt_name": "demo",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-all-prompts",
                {"server_url": "https://example.com/mcp", "analyzers": ["yara"]},
            ),
            (
                "/scan-resource",
                {
                    "server_url": "https://example.com/mcp",
                    "resource_uri": "res://x",
                    "analyzers": ["yara"],
                },
            ),
            (
                "/scan-all-resources",
                {"server_url": "https://example.com/mcp", "analyzers": ["yara"]},
            ),
            (
                "/scan-instructions",
                {"server_url": "https://example.com/mcp", "analyzers": ["yara"]},
            ),
        ],
    )
    def test_enable_meta_omitted_does_not_add_meta(
        self, captured_factory_and_scanner, endpoint, payload
    ):
        """No ``enable_meta`` flag → META must NOT appear in either site."""
        captured, app = captured_factory_and_scanner
        client = TestClient(app)

        response = client.post(endpoint, json=payload)
        assert response.status_code == 200, response.text

        assert AnalyzerEnum.META not in (captured["factory_analyzers"] or [])
        assert AnalyzerEnum.META not in (captured["scan_call_analyzers"] or [])

    def test_explicit_meta_in_analyzers_is_honoured(
        self, captured_factory_and_scanner
    ):
        """``analyzers=["yara", "meta"]`` runs meta even without ``enable_meta``."""
        captured, app = captured_factory_and_scanner
        client = TestClient(app)

        response = client.post(
            "/scan-tool",
            json={
                "server_url": "https://example.com/mcp",
                "tool_name": "demo",
                "analyzers": ["yara", "meta"],
            },
        )
        assert response.status_code == 200, response.text
        assert captured["factory_analyzers"] == [AnalyzerEnum.YARA, AnalyzerEnum.META]
        assert captured["scan_call_analyzers"] == [AnalyzerEnum.YARA, AnalyzerEnum.META]

    def test_enable_meta_with_explicit_meta_does_not_duplicate(
        self, captured_factory_and_scanner
    ):
        """``enable_meta=True`` is a no-op when META is already present."""
        captured, app = captured_factory_and_scanner
        client = TestClient(app)

        response = client.post(
            "/scan-tool",
            json={
                "server_url": "https://example.com/mcp",
                "tool_name": "demo",
                "analyzers": ["yara", "meta"],
                "enable_meta": True,
            },
        )
        assert response.status_code == 200, response.text
        assert captured["factory_analyzers"].count(AnalyzerEnum.META) == 1
        assert captured["scan_call_analyzers"].count(AnalyzerEnum.META) == 1


# ---------------------------------------------------------------------------
# _prepare_scanner_config — keep LLM credentials wired for META / BEHAVIORAL
# ---------------------------------------------------------------------------


class TestPrepareScannerConfigLLMCredentials:
    """``_prepare_scanner_config`` must not blank LLM credentials when any
    LLM-backed analyzer (LLM, BEHAVIORAL, META) is requested.

    Regression: prior to this fix, ``llm_scan = AnalyzerEnum.LLM in analyzers``
    only checked the literal LLM analyzer. ``analyzers=["yara","meta"]`` would
    pass ``llm_scan=False`` to the no-op blanking branch, and the resulting
    Scanner would refuse to initialize the meta-analyzer with a confusing
    "MCP_SCANNER_LLM_API_KEY not configured" 404, even though the operator's
    env was correctly set.
    """

    @pytest.fixture(autouse=True)
    def _set_env(self, monkeypatch):
        """Provide an LLM API key in the module-level globals."""
        monkeypatch.setattr("mcpscanner.api.api.LLM_API_KEY", "fake-llm-key")
        monkeypatch.setattr("mcpscanner.api.api.LLM_MODEL", "gpt-4o")
        monkeypatch.setattr("mcpscanner.api.api.API_KEY", "")
        monkeypatch.setattr("mcpscanner.api.api.AWS_REGION", "")
        monkeypatch.setattr("mcpscanner.api.api.AWS_PROFILE", "")
        monkeypatch.setattr("mcpscanner.api.api.AWS_SESSION_TOKEN", "")

    def test_meta_only_keeps_llm_key(self):
        from mcpscanner.api.api import _prepare_scanner_config

        api_key, _, llm_api_key, *_ = _prepare_scanner_config(
            [AnalyzerEnum.YARA, AnalyzerEnum.META]
        )
        assert api_key == ""
        assert llm_api_key == "fake-llm-key", (
            "LLM API key must NOT be blanked when META is requested — "
            "the meta-analyzer needs it to make its second-pass LLM call."
        )

    def test_behavioral_only_keeps_llm_key(self):
        from mcpscanner.api.api import _prepare_scanner_config

        _, _, llm_api_key, *_ = _prepare_scanner_config(
            [AnalyzerEnum.YARA, AnalyzerEnum.BEHAVIORAL]
        )
        assert llm_api_key == "fake-llm-key"

    def test_llm_explicitly_keeps_llm_key(self):
        """Existing behaviour preserved: explicit LLM also keeps the key."""
        from mcpscanner.api.api import _prepare_scanner_config

        _, _, llm_api_key, *_ = _prepare_scanner_config(
            [AnalyzerEnum.YARA, AnalyzerEnum.LLM]
        )
        assert llm_api_key == "fake-llm-key"

    def test_no_llm_backed_analyzer_blanks_llm_key(self):
        """Existing behaviour preserved: pure YARA blanks the key."""
        from mcpscanner.api.api import _prepare_scanner_config

        _, _, llm_api_key, *_ = _prepare_scanner_config([AnalyzerEnum.YARA])
        assert llm_api_key == ""


# ---------------------------------------------------------------------------
# Specific request types inherit ``enable_meta`` from APIScanRequest
# ---------------------------------------------------------------------------


class TestSpecificRequestParity:
    """All specific request types inherit the ``enable_meta`` field."""

    @pytest.mark.parametrize(
        "request_cls, kwargs",
        [
            (SpecificToolScanRequest, {"tool_name": "t"}),
            (SpecificPromptScanRequest, {"prompt_name": "p"}),
            (SpecificResourceScanRequest, {"resource_uri": "res://x"}),
            (SpecificInstructionsScanRequest, {}),
        ],
    )
    def test_inherits_enable_meta(self, request_cls, kwargs):
        req = request_cls(
            server_url="https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
            enable_meta=True,
            **kwargs,
        )
        assert req.enable_meta is True
        assert AnalyzerEnum.META in req.resolved_analyzers()
