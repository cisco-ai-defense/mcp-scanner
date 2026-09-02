# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Tests for parallel alignment batch execution."""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    AlignmentOrchestrator,
)
from tests.behavioral.test_code_review_fixes import _cfg


def _ctx(name: str) -> SimpleNamespace:
    """Create a test context with the specified name.
    
    Parameters:
    	name (str): The context name.
    
    Returns:
    	SimpleNamespace: A context object containing the name.
    """
    return SimpleNamespace(name=name)


@pytest.mark.asyncio
async def test_parallel_batches_run_concurrently(monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "BEHAVIORAL_LLM_BATCH_CONCURRENCY", 3)

    orch = AlignmentOrchestrator(_cfg())
    active = 0
    peak = 0
    lock = asyncio.Lock()

    async def _verify(_prompt: str) -> str:
        nonlocal active, peak
        async with lock:
            active += 1
            peak = max(peak, active)
        await asyncio.sleep(0.05)
        async with lock:
            active -= 1
        return '{"results": [{"mismatch_detected": false}]}'

    orch.prompt_builder = SimpleNamespace(
        build_batch_analysis_content=lambda batch: f"body:{len(batch)}",
        wrap_batch_prompt=lambda batch, body: body,
        build_prompt=lambda _c: "p",
    )
    orch.llm_client = SimpleNamespace(verify_alignment=_verify)
    orch.response_validator.validate_batch = (
        lambda _response, count: [{"mismatch_detected": False} for _ in range(count)]
    )

    ctxs = [_ctx(f"fn{i}") for i in range(6)]
    start = time.perf_counter()
    results = await orch.check_alignment_batch(ctxs, batch_size=1, max_concurrency=3)
    elapsed = time.perf_counter() - start

    assert results == []
    assert peak >= 2, f"expected concurrent batches, peak={peak}"
    assert elapsed < 0.25, f"parallel batches too slow: {elapsed:.2f}s"
    assert orch.stats["total_analyzed"] == 6
    assert orch.stats["no_mismatch"] == 6
