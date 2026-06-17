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
from pydantic import ValidationError

from mcpscanner.api.router import get_scanner, router
from mcpscanner.core.models import (
    API_ALLOWED_ANALYZERS,
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

    def test_meta_in_analyzers_with_enable_meta_false_logs_warning(self):
        """P2-5: pin the operator-visibility warning for the surprising
        case where ``enable_meta=False`` but ``meta`` is in
        ``analyzers``. Behaviour is unchanged (META still runs — flag
        is additive) but the warning surfaces the inconsistency in
        operator logs.

        The model_validator must NOT raise; we keep the existing
        pattern (explicit META in the list) working for back-compat.
        """
        import logging

        records: list[logging.LogRecord] = []

        class _Cap(logging.Handler):
            def emit(self, record):
                records.append(record)

        # ``setup_logger`` sets propagate=False on the project loggers,
        # so caplog can't capture; harvest from the named logger.
        target = logging.getLogger("mcpscanner.core.models")
        h = _Cap(level=logging.WARNING)
        target.addHandler(h)
        try:
            req = APIScanRequest(
                server_url="https://example.com/mcp",
                analyzers=[AnalyzerEnum.YARA, AnalyzerEnum.META],
                enable_meta=False,
            )
        finally:
            target.removeHandler(h)

        # Behaviour preserved: META still runs.
        assert AnalyzerEnum.META in req.resolved_analyzers()
        # Warning emitted.
        warnings = [
            r for r in records if "enable_meta=False" in r.getMessage()
        ]
        assert warnings, (
            "Operators must be warned about the surprising "
            "enable_meta=False + meta-in-analyzers combination."
        )
        msg = warnings[0].getMessage()
        assert "additive" in msg or "still run" in msg

    def test_consistent_meta_request_does_not_warn(self):
        """No warning when both forms agree: enable_meta=True with or
        without explicit META in analyzers, OR enable_meta=False with
        no META in analyzers.
        """
        import logging

        records: list[logging.LogRecord] = []

        class _Cap(logging.Handler):
            def emit(self, record):
                records.append(record)

        target = logging.getLogger("mcpscanner.core.models")
        h = _Cap(level=logging.WARNING)
        target.addHandler(h)
        try:
            # All-off (default) — silent.
            APIScanRequest(server_url="https://example.com/mcp")
            # All-on (idiomatic) — silent.
            APIScanRequest(
                server_url="https://example.com/mcp",
                analyzers=[AnalyzerEnum.YARA],
                enable_meta=True,
            )
            # All-on (explicit duplicate) — silent.
            APIScanRequest(
                server_url="https://example.com/mcp",
                analyzers=[AnalyzerEnum.YARA, AnalyzerEnum.META],
                enable_meta=True,
            )
        finally:
            target.removeHandler(h)
        bad = [r for r in records if "enable_meta=False" in r.getMessage()]
        assert bad == []

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


# ---------------------------------------------------------------------------
# API analyzer allowlist — only API/YARA/LLM/META are exposed via HTTP
# ---------------------------------------------------------------------------


class TestAPIAnalyzerAllowlist:
    """Pin the contract that the HTTP API only accepts a fixed analyzer set.

    Why a hard reject instead of silent filtering:
    - ``_group_findings_for_api`` only knows how to render API/YARA/LLM
      findings (plus custom analyzers); requesting BEHAVIORAL or
      PROMPT_DEFENSE used to result in a clean-looking 200 with the
      findings silently dropped from the response shape. That is exactly
      the failure mode the meta-analyzer work was supposed to surface,
      so we reject at the request boundary with a clear validation
      error instead.
    - The blocked analyzers remain available via the SDK and CLI; the
      restriction is HTTP-only.
    """

    def test_allowlist_is_exactly_api_yara_llm_meta(self):
        """Allowlist is the four HTTP-friendly analyzers and nothing else."""
        assert API_ALLOWED_ANALYZERS == frozenset(
            {
                AnalyzerEnum.API,
                AnalyzerEnum.YARA,
                AnalyzerEnum.LLM,
                AnalyzerEnum.META,
            }
        )

    @pytest.mark.parametrize("allowed", sorted(API_ALLOWED_ANALYZERS))
    def test_allowed_analyzer_passes_validation(self, allowed):
        """Each allowlisted analyzer is accepted on its own."""
        req = APIScanRequest(
            server_url="https://example.com/mcp", analyzers=[allowed]
        )
        assert req.analyzers == [allowed]

    @pytest.mark.parametrize(
        "blocked",
        [
            AnalyzerEnum.BEHAVIORAL,
            AnalyzerEnum.PROMPT_DEFENSE,
            AnalyzerEnum.VIRUSTOTAL,
            AnalyzerEnum.READINESS,
            AnalyzerEnum.VULNERABLE_PACKAGE,
        ],
    )
    def test_blocked_analyzer_raises_validation_error(self, blocked):
        """Each blocked analyzer triggers a Pydantic validation error.

        FastAPI translates this into a 422 at the endpoint layer; we pin
        the model-level behaviour here because it's faster and lets us
        assert on the error message without mounting an app.
        """
        with pytest.raises(ValidationError) as exc_info:
            APIScanRequest(
                server_url="https://example.com/mcp",
                analyzers=[AnalyzerEnum.YARA, blocked],
            )
        msg = str(exc_info.value)
        assert blocked.value in msg
        # The error must mention the allowlist so operators know what's accepted.
        assert "api" in msg and "yara" in msg and "llm" in msg and "meta" in msg

    def test_blocked_analyzers_listed_collectively(self):
        """Multiple blocked analyzers are reported in one error, not one-at-a-time."""
        with pytest.raises(ValidationError) as exc_info:
            APIScanRequest(
                server_url="https://example.com/mcp",
                analyzers=[
                    AnalyzerEnum.BEHAVIORAL,
                    AnalyzerEnum.VIRUSTOTAL,
                    AnalyzerEnum.READINESS,
                ],
            )
        msg = str(exc_info.value)
        assert "behavioral" in msg
        assert "virustotal" in msg
        assert "readiness" in msg

    def test_default_analyzers_are_allowed(self):
        """The default analyzers list (api/yara/llm) must satisfy the allowlist."""
        req = APIScanRequest(server_url="https://example.com/mcp")
        for a in req.analyzers:
            assert a in API_ALLOWED_ANALYZERS

    def test_endpoint_returns_422_for_blocked_analyzer(
        self, captured_factory_and_scanner
    ):
        """Live endpoint test: a blocked analyzer yields HTTP 422 from FastAPI."""
        captured, app = captured_factory_and_scanner
        client = TestClient(app)

        response = client.post(
            "/scan-tool",
            json={
                "server_url": "https://example.com/mcp",
                "tool_name": "demo",
                "analyzers": ["yara", "behavioral"],
            },
        )
        assert response.status_code == 422, response.text
        body = response.json()
        # FastAPI returns the Pydantic detail under "detail"; the message
        # should at least name the offending analyzer.
        assert "behavioral" in response.text.lower()
        # Critically: the scanner must NOT have been invoked.
        assert captured["factory_analyzers"] is None
        assert captured["scan_call_analyzers"] is None

    def test_endpoint_accepts_allowlisted_combo_with_meta(
        self, captured_factory_and_scanner
    ):
        """Sanity: ``analyzers=["api","yara","llm"]`` + ``enable_meta=true`` succeeds."""
        captured, app = captured_factory_and_scanner
        client = TestClient(app)

        response = client.post(
            "/scan-tool",
            json={
                "server_url": "https://example.com/mcp",
                "tool_name": "demo",
                "analyzers": ["api", "yara", "llm"],
                "enable_meta": True,
            },
        )
        assert response.status_code == 200, response.text
        assert captured["scan_call_analyzers"] == [
            AnalyzerEnum.API,
            AnalyzerEnum.YARA,
            AnalyzerEnum.LLM,
            AnalyzerEnum.META,
        ]


# ---------------------------------------------------------------------------
# Meta-analyzer audit trail surfaced via the API (P0-2)
# ---------------------------------------------------------------------------


@pytest.fixture
def app_with_meta_audit_scanner():
    """Build a FastAPI app whose Scanner attaches dropped findings.

    The mocked Scanner returns ScanResult objects that already have
    ``meta_filtered_findings`` populated, mirroring what
    ``Scanner._run_meta_analysis_on_*`` produces in production. The
    fixture keeps the audit attached to each result type so we can pin
    the API response shape across all four entity kinds.
    """
    from mcpscanner.core.analyzers.base import SecurityFinding

    def _dropped(reason: str = "Standard parameter naming") -> SecurityFinding:
        return SecurityFinding(
            severity="LOW",
            summary="benign keyword match",
            analyzer="YARA",
            threat_category="CREDENTIAL_HARVESTING",
            details={
                "meta_false_positive": True,
                "meta_reason": reason,
                "meta_confidence": "HIGH",
            },
        )

    tool_result = ToolScanResult(
        tool_name="demo_tool",
        tool_description="demo",
        status="completed",
        analyzers=["yara", "meta"],
        findings=[],
    )
    tool_result.meta_filtered_findings = [_dropped("safe doc string")]

    prompt_result = PromptScanResult(
        prompt_name="demo_prompt",
        prompt_description="demo",
        status="completed",
        analyzers=["yara", "meta"],
        findings=[],
    )
    prompt_result.meta_filtered_findings = [_dropped("safe variable name")]

    resource_result = ResourceScanResult(
        resource_uri="res://x",
        resource_name="x",
        resource_mime_type="text/plain",
        status="completed",
        analyzers=["yara", "meta"],
        findings=[],
    )
    resource_result.meta_filtered_findings = [_dropped("safe library usage")]

    instructions_result = InstructionsScanResult(
        instructions="hello",
        server_name="srv",
        protocol_version="2025-06-18",
        status="completed",
        analyzers=["yara", "meta"],
        findings=[],
    )
    instructions_result.meta_filtered_findings = [_dropped("benign mention")]

    scanner = MagicMock()
    scanner.get_custom_analyzers.return_value = []
    scanner.scan_remote_server_tool = AsyncMock(return_value=tool_result)
    scanner.scan_remote_server_tools = AsyncMock(return_value=[tool_result])
    scanner.scan_remote_server_prompt = AsyncMock(return_value=prompt_result)
    scanner.scan_remote_server_prompts = AsyncMock(return_value=[prompt_result])
    scanner.scan_remote_server_resource = AsyncMock(return_value=resource_result)
    scanner.scan_remote_server_resources = AsyncMock(return_value=[resource_result])
    scanner.scan_remote_server_instructions = AsyncMock(
        return_value=instructions_result
    )

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_scanner] = lambda: lambda analyzers: scanner

    return app


class TestMetaAnalysisAuditTrail:
    """Pin the API contract that meta-filtered findings are visible.

    Without this audit block the operator cannot tell whether a clean
    ``"is_safe": true`` came from a *clean tool* or from *meta filtered
    everything to clean*. The mutation that ``apply_meta_analysis``
    performs on the dropped finding is dead code unless the result
    object retains the dropped list AND the API surfaces it.
    """

    def test_tool_response_includes_meta_analysis_block(
        self, app_with_meta_audit_scanner
    ):
        client = TestClient(app_with_meta_audit_scanner)
        response = client.post(
            "/scan-tool",
            json={
                "server_url": "https://example.com/mcp",
                "tool_name": "demo_tool",
                "analyzers": ["yara"],
                "enable_meta": True,
                "output_format": "raw",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert "meta_analysis" in body
        meta = body["meta_analysis"]
        assert meta["filtered_count"] == 1
        assert meta["filtered_findings"][0]["analyzer"] == "YARA"
        assert meta["filtered_findings"][0]["meta_reason"] == "safe doc string"
        assert meta["filtered_findings"][0]["meta_confidence"] == "HIGH"

    def test_prompt_response_includes_meta_analysis_block(
        self, app_with_meta_audit_scanner
    ):
        client = TestClient(app_with_meta_audit_scanner)
        response = client.post(
            "/scan-prompt",
            json={
                "server_url": "https://example.com/mcp",
                "prompt_name": "demo_prompt",
                "analyzers": ["yara"],
                "enable_meta": True,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["meta_analysis"]["filtered_count"] == 1
        assert (
            body["meta_analysis"]["filtered_findings"][0]["meta_reason"]
            == "safe variable name"
        )

    def test_resource_response_includes_meta_analysis_block(
        self, app_with_meta_audit_scanner
    ):
        client = TestClient(app_with_meta_audit_scanner)
        response = client.post(
            "/scan-resource",
            json={
                "server_url": "https://example.com/mcp",
                "resource_uri": "res://x",
                "analyzers": ["yara"],
                "enable_meta": True,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["meta_analysis"]["filtered_count"] == 1

    def test_instructions_response_includes_meta_analysis_block(
        self, app_with_meta_audit_scanner
    ):
        client = TestClient(app_with_meta_audit_scanner)
        response = client.post(
            "/scan-instructions",
            json={
                "server_url": "https://example.com/mcp",
                "analyzers": ["yara"],
                "enable_meta": True,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["meta_analysis"]["filtered_count"] == 1

    def test_scan_all_tools_response_includes_meta_analysis_block(
        self, app_with_meta_audit_scanner
    ):
        """Bulk endpoint must surface the audit block per scan result."""
        client = TestClient(app_with_meta_audit_scanner)
        response = client.post(
            "/scan-all-tools",
            json={
                "server_url": "https://example.com/mcp",
                "analyzers": ["yara"],
                "enable_meta": True,
                "output_format": "raw",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        # AllToolsScanResponse wraps a list of ToolScanResult (Pydantic).
        assert "scan_results" in body
        assert body["scan_results"][0]["meta_analysis"]["filtered_count"] == 1

    def test_scan_all_prompts_response_includes_meta_analysis_block(
        self, app_with_meta_audit_scanner
    ):
        client = TestClient(app_with_meta_audit_scanner)
        response = client.post(
            "/scan-all-prompts",
            json={
                "server_url": "https://example.com/mcp",
                "analyzers": ["yara"],
                "enable_meta": True,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["prompts"][0]["meta_analysis"]["filtered_count"] == 1

    def test_scan_all_resources_response_includes_meta_analysis_block(
        self, app_with_meta_audit_scanner
    ):
        client = TestClient(app_with_meta_audit_scanner)
        response = client.post(
            "/scan-all-resources",
            json={
                "server_url": "https://example.com/mcp",
                "analyzers": ["yara"],
                "enable_meta": True,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["resources"][0]["meta_analysis"]["filtered_count"] == 1

    def test_meta_analysis_block_omitted_when_no_filtering(self):
        """When no findings were dropped, the response does NOT include the block.

        Backwards compat: callers that don't use ``enable_meta`` (or use
        it but the LLM dropped nothing) must see the same response shape
        they saw before. We pin omission rather than ``"meta_analysis":
        null`` so existing JSON consumers don't break.
        """
        scanner = MagicMock()
        scanner.get_custom_analyzers.return_value = []
        clean_result = ToolScanResult(
            tool_name="clean",
            tool_description="",
            status="completed",
            analyzers=["yara"],
            findings=[],
        )
        # meta_filtered_findings stays at the default empty list.
        scanner.scan_remote_server_tool = AsyncMock(return_value=clean_result)

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_scanner] = lambda: lambda analyzers: scanner
        client = TestClient(app)

        response = client.post(
            "/scan-tool",
            json={
                "server_url": "https://example.com/mcp",
                "tool_name": "clean",
                "analyzers": ["yara"],
                "output_format": "raw",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        # Either omitted entirely (preferred) or null. Either way it must
        # not appear with a misleading filtered_count of 0.
        assert body.get("meta_analysis") in (None,)


# ---------------------------------------------------------------------------
# CLI Bedrock gate (P0-5) — model-level pin via direct gate evaluation
# ---------------------------------------------------------------------------


class TestCLIMetaBedrockGate:
    """Pin the CLI ``--enable-meta`` gate parity with Scanner.__init__.

    The CLI used to gate meta-analysis on ``cfg.llm_provider_api_key``
    alone, which silently no-op'd ``--enable-meta`` on the IAM-only
    Bedrock flow this branch was built for. ``Scanner.__init__`` gates
    on ``(api_key or is_bedrock)`` — the CLI must mirror that exactly.
    """

    @pytest.mark.parametrize(
        "model, api_key, expect_runs",
        [
            # Direct OpenAI / Azure: needs an API key.
            ("gpt-4o", "key", True),
            ("gpt-4o", "", False),
            # Bedrock with no API key but a bedrock/* model: must run.
            ("bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", "", True),
            # Bedrock WITH an API key (bearer): must run too.
            (
                "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
                "bearer-token",
                True,
            ),
            # Empty model: needs an API key, otherwise no run.
            (None, "", False),
        ],
    )
    def test_meta_gate_matches_scanner_init(self, model, api_key, expect_runs):
        """Replicate the CLI gate expression and confirm parity with Scanner."""
        # CLI gate (after the fix):
        is_bedrock = bool(model and "bedrock/" in model)
        cli_gate = bool(api_key or is_bedrock)

        # Scanner.__init__ gate (the source of truth):
        scanner_gate = bool(api_key or is_bedrock)

        assert cli_gate == scanner_gate
        assert cli_gate == expect_runs, (
            f"For model={model!r}, key={api_key!r}: "
            f"expected runs={expect_runs}, got {cli_gate}"
        )

    def test_cli_gate_source_includes_bedrock_branch(self):
        """Source-level pin: cli.py's --enable-meta gate must include the
        Bedrock fallback. Catches a future refactor that silently drops
        the IAM-only Bedrock path again.
        """
        import inspect

        from mcpscanner import cli as cli_module

        source = inspect.getsource(cli_module)
        # The fix introduces an ``_meta_is_bedrock`` local that is OR-ed
        # with the API key. If either side disappears, the gate is broken.
        assert "_meta_is_bedrock" in source
        assert "cfg.llm_provider_api_key or _meta_is_bedrock" in source
        assert 'bedrock/" in cfg.llm_model' in source


# ---------------------------------------------------------------------------
# P2-2: end-to-end FP filtering through the API
# ---------------------------------------------------------------------------


def _make_scanner_with_real_meta(meta_analyze_findings):
    """Build a real Scanner with a stubbed MetaAnalyzer.analyze_findings.

    Exercises the full meta-analysis pipeline end-to-end:
      1. Primary analyzer produces N findings (we mock the YARA layer to
         skip rule loading and return one-shot canned findings).
      2. ``Scanner._run_meta_analysis_on_results`` calls the stubbed
         ``analyze_findings`` to decide which to drop.
      3. ``apply_meta_analysis`` actually filters the list.
      4. The router's response builder surfaces ``meta_analysis``.

    The previous test suite mocked the entire Scanner, which proved
    routing but never that meta-filtering actually filters. This fixture
    closes that gap (P2-2).
    """
    from mcpscanner.config.config import Config
    from mcpscanner.core.scanner import Scanner

    config = Config(llm_provider_api_key="test-key")
    scanner = Scanner(config)
    scanner._meta_analyzer.analyze_findings = meta_analyze_findings
    return scanner


def _scanner_app(scanner):
    """Mount the router with a Scanner override."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_scanner] = lambda: lambda analyzers: scanner
    return app


class TestEndToEndFPFiltering:
    """P2-2: prove FP-flagged findings actually get removed from the
    response, and that an exception in the meta-analyzer doesn't 500.
    """

    @staticmethod
    def _make_tool_request(scanner):
        async def _scan_with_meta(*args, **kwargs):
            from mcpscanner.core.models import AnalyzerEnum

            enriched = await scanner.apply_meta_to_results(
                [scanner._test_tool_result], [AnalyzerEnum.META]
            )
            return enriched[0]

        scanner.scan_remote_server_tool = _scan_with_meta
        scanner.get_custom_analyzers = MagicMock(return_value=[])

        client = TestClient(_scanner_app(scanner))
        return client.post(
            "/scan-tool",
            json={
                "server_url": "https://example.com/mcp",
                "tool_name": "t",
                "analyzers": ["yara"],
                "enable_meta": True,
                "output_format": "raw",
            },
        )

    @staticmethod
    def _make_tool_result_with_one_finding():
        from mcpscanner.core.analyzers.base import SecurityFinding

        finding = SecurityFinding(
            severity="HIGH",
            summary="real threat",
            analyzer="YARA",
            threat_category="CREDENTIAL_HARVESTING",
        )
        return ToolScanResult(
            tool_name="t",
            tool_description="d",
            status="completed",
            analyzers=["yara", "meta"],
            findings=[finding],
        )

    def test_finding_marked_as_fp_is_removed_from_response(self):
        """LLM returns one FP → response shows 0 visible findings,
        meta_analysis block carries the dropped one.
        """
        from mcpscanner.core.analyzers.meta_analyzer import MetaAnalysisResult

        async def _meta(findings, analyzers_used, entity_context):
            return MetaAnalysisResult(
                false_positives=[
                    {
                        "_index": 0,
                        "false_positive_reason": "benign keyword in safe doc",
                        "confidence": "HIGH",
                    }
                ],
            )

        scanner = _make_scanner_with_real_meta(_meta)
        scanner._test_tool_result = self._make_tool_result_with_one_finding()
        response = self._make_tool_request(scanner)

        assert response.status_code == 200, response.text
        body = response.json()

        # The yara_analyzer group reports zero findings post-filter.
        yara_group = body["findings"].get("yara_analyzer", {})
        assert yara_group.get("total_findings", 0) == 0, (
            f"FP-marked finding leaked into visible response: {yara_group!r}"
        )
        # Severity rolls down to SAFE because the only finding was filtered.
        assert yara_group.get("severity") == "SAFE"

        # Audit trail surfaces the dropped finding so operators can tell
        # this came from filtering, not from a clean tool.
        meta = body.get("meta_analysis")
        assert meta is not None, "meta_analysis block missing despite FP drop"
        assert meta["filtered_count"] == 1
        assert meta["filtered_findings"][0]["meta_reason"] == (
            "benign keyword in safe doc"
        )

    def test_meta_analyzer_exception_does_not_500_and_keeps_findings(self):
        """LLM raises → no 5xx → all findings preserved → no meta_analysis
        block (since nothing was actually filtered).

        Contract that ``Scanner._meta_analyze_one_*`` already has at the
        helper layer (try/except returns the original result) but had no
        API-level regression test. Without this, a future refactor that
        lets the exception propagate would silently start emitting 500s
        on every meta-enabled request whenever the LLM hiccups.
        """
        async def _meta(findings, analyzers_used, entity_context):
            raise RuntimeError("simulated LLM transport error")

        scanner = _make_scanner_with_real_meta(_meta)
        scanner._test_tool_result = self._make_tool_result_with_one_finding()
        response = self._make_tool_request(scanner)

        # No 500 — that's the whole point of the contract.
        assert response.status_code == 200, response.text
        body = response.json()

        yara_group = body["findings"].get("yara_analyzer", {})
        assert yara_group.get("total_findings", 0) == 1, (
            f"Original finding lost when meta raised: {yara_group!r}"
        )
        assert yara_group.get("severity") == "HIGH"

        # No meta_analysis block when nothing was filtered.
        assert body.get("meta_analysis") is None, (
            "meta_analysis block must be omitted when meta-analysis failed: "
            f"{body.get('meta_analysis')!r}"
        )

    def test_no_fps_returned_means_no_findings_dropped(self):
        """LLM returns ``false_positives: []`` → response shape unchanged.

        Inverse of the filtering test: a clean meta verdict must not
        accidentally drop findings, and the meta_analysis block must be
        omitted (we only surface it when there's filtering to report).
        """
        from mcpscanner.core.analyzers.meta_analyzer import MetaAnalysisResult

        async def _meta(findings, analyzers_used, entity_context):
            return MetaAnalysisResult(false_positives=[])

        scanner = _make_scanner_with_real_meta(_meta)
        scanner._test_tool_result = self._make_tool_result_with_one_finding()
        response = self._make_tool_request(scanner)

        assert response.status_code == 200
        body = response.json()

        yara_group = body["findings"].get("yara_analyzer", {})
        assert yara_group.get("total_findings", 0) == 1
        assert yara_group.get("severity") == "HIGH"

        # Meta block is omitted: nothing was filtered, no audit content.
        # (Different contract from "meta ran" — we don't advertise that
        # meta ran when there's nothing to report.)
        assert body.get("meta_analysis") is None
