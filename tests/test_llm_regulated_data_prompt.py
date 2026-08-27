"""LLM prompt tests for regulated-data (PII/PHI/PCI) detection and false positives."""

from __future__ import annotations

import json
import os

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer

# Import scenario definitions from the probe script (single source of truth)
from scripts.phi_pci_pii_fp_probe import (  # noqa: E402
    FALSE_POSITIVE_SCENARIOS,
    TRUE_POSITIVE_SCENARIOS,
    build_content,
    check_scenario,
    classify,
)

pytestmark = pytest.mark.integration


def _bedrock_configured() -> bool:
    return bool(
        os.getenv("MCP_SCANNER_LLM_MODEL")
        or os.getenv("MCP_SCANNER_LLM_API_KEY")
        or os.getenv("AWS_PROFILE")
        or os.getenv("AWS_ACCESS_KEY_ID")
    )


@pytest.fixture(scope="module")
def llm_analyzer() -> LLMAnalyzer:
    return LLMAnalyzer(Config())


@pytest.mark.parametrize(
    "scenario",
    FALSE_POSITIVE_SCENARIOS,
    ids=[s.name for s in FALSE_POSITIVE_SCENARIOS],
)
@pytest.mark.skipif(not _bedrock_configured(), reason="LLM credentials not configured")
@pytest.mark.asyncio
async def test_regulated_data_false_positives_stay_safe(
    llm_analyzer: LLMAnalyzer, scenario
) -> None:
    label, threats = await classify(llm_analyzer, scenario)
    assert check_scenario(scenario, label, threats), (
        f"Expected SAFE for {scenario.name} ({scenario.category}), "
        f"got {label} threats={threats}. "
        f"Content preview: {build_content(scenario)[:200]}..."
    )


@pytest.mark.parametrize(
    "scenario",
    TRUE_POSITIVE_SCENARIOS,
    ids=[s.name for s in TRUE_POSITIVE_SCENARIOS],
)
@pytest.mark.skipif(not _bedrock_configured(), reason="LLM credentials not configured")
@pytest.mark.asyncio
async def test_regulated_data_true_positives_still_flagged(
    llm_analyzer: LLMAnalyzer, scenario
) -> None:
    label, threats = await classify(llm_analyzer, scenario)
    assert check_scenario(scenario, label, threats), (
        f"Expected HIGH/{scenario.expect_threats} for {scenario.name}, "
        f"got {label} threats={threats}"
    )


def test_prompt_includes_regulated_data_guidance() -> None:
    """Static check: prompt documents PHI/PCI/PII rules and defensive exceptions."""
    analyzer = LLMAnalyzer(Config())
    prompt = analyzer._threat_analysis_prompt
    for needle in (
        "Regulated sensitive data",
        "PHI",
        "PCI",
        "PII",
        "anonymize/redact/de-identify PII",
        "get_medical_data",
        "get_payment_data",
        "DO NOT flag regulated-data tools when ALL of these apply",
    ):
        assert needle in prompt, f"Missing prompt guidance: {needle!r}"


def test_false_positive_scenario_catalog_is_non_empty() -> None:
    assert len(FALSE_POSITIVE_SCENARIOS) >= 10
    assert len(TRUE_POSITIVE_SCENARIOS) >= 2
    categories = {s.category for s in FALSE_POSITIVE_SCENARIOS}
    assert "defensive_pii" in categories
    assert "authorized_payment" in categories
    assert "authorized_healthcare" in categories
