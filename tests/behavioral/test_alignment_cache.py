# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-scan alignment result caching."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.analyzers.behavioral.alignment.alignment_cache import (
    AlignmentResultCache,
)
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    AlignmentOrchestrator,
)
from mcpscanner.core.analyzers.behavioral.alignment.alignment_prompt_builder import (
    AlignmentPromptBuilder,
)
from mcpscanner.core.static_analysis.context_extractor import FunctionContext


def _minimal_function_context(**overrides):
    """Create a minimal function context for tests with optional field overrides.
    
    Parameters:
        overrides: Function context fields to replace in the default test context.
    
    Returns:
        FunctionContext: A context populated with minimal test-tool metadata.
    """
    base = dict(
        name="test_tool",
        decorator_types=["@mcp.tool"],
        imports=[],
        function_calls=[],
        assignments=[],
        control_flow={},
        parameter_flows=[],
        constants={},
        variable_dependencies={},
        has_file_operations=False,
        has_network_operations=False,
        has_subprocess_calls=False,
        has_eval_exec=False,
        has_dangerous_imports=False,
        docstring="Returns the input unchanged.",
    )
    base.update(overrides)
    return FunctionContext(**base)


class TestAlignmentResultCache:
    def test_same_evidence_produces_same_key(self):
        builder = AlignmentPromptBuilder()
        cache = AlignmentResultCache(model="test-model")
        ctx = _minimal_function_context()
        key_a = cache.key_for(ctx, prompt_builder=builder)
        key_b = cache.key_for(ctx, prompt_builder=builder)
        assert key_a == key_b

    def test_docstring_change_changes_key(self):
        builder = AlignmentPromptBuilder()
        cache = AlignmentResultCache(model="test-model")
        key_a = cache.key_for(
            _minimal_function_context(docstring="one"),
            prompt_builder=builder,
        )
        key_b = cache.key_for(
            _minimal_function_context(docstring="two"),
            prompt_builder=builder,
        )
        assert key_a != key_b


class TestAlignmentOrchestratorCache:
    def _new_orchestrator(self) -> AlignmentOrchestrator:
        """Create an alignment orchestrator with a mocked asynchronous alignment verifier."""
        config = MagicMock()
        orch = AlignmentOrchestrator(config)
        orch.llm_client.verify_alignment = AsyncMock()
        return orch

    @pytest.mark.asyncio
    async def test_cache_hit_skips_llm(self, monkeypatch):
        monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_CACHE_ENABLED", True)
        orch = self._new_orchestrator()
        ctx = _minimal_function_context()
        mismatch = {
            "mismatch_detected": True,
            "threat_name": "DATA EXFILTRATION",
            "summary": "cached",
        }
        cache_key = orch._result_cache.key_for(
            ctx, prompt_builder=orch.prompt_builder
        )
        orch._result_cache.put(cache_key, mismatch)

        result = await orch.check_alignment(ctx)

        orch.llm_client.verify_alignment.assert_not_called()
        assert result is not None
        assert result[0]["summary"] == "cached"
        assert orch.stats["cache_hits"] == 1

    @pytest.mark.asyncio
    async def test_reset_stats_clears_cache(self, monkeypatch):
        monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_CACHE_ENABLED", True)
        orch = self._new_orchestrator()
        ctx = _minimal_function_context()
        cache_key = orch._result_cache.key_for(
            ctx, prompt_builder=orch.prompt_builder
        )
        orch._result_cache.put(
            cache_key,
            {"mismatch_detected": False, "threat_name": ""},
        )
        orch.reset_stats()
        assert orch._result_cache.get(cache_key) is None

    @pytest.mark.asyncio
    async def test_cache_disabled_calls_llm(self, monkeypatch):
        monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_CACHE_ENABLED", False)
        orch = self._new_orchestrator()
        orch.llm_client.verify_alignment.return_value = '{"mismatch_detected": false}'
        ctx = _minimal_function_context()

        await orch.check_alignment(ctx)

        orch.llm_client.verify_alignment.assert_called_once()
