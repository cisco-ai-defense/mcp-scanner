"""Static tests for regulated-data (PII/PHI/PCI) LLM prompt guidance.

These tests run in CI without LLM credentials. Live LLM validation is manual.
"""

from __future__ import annotations

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
from tests.regulated_data_scenarios import (
    FALSE_POSITIVE_SCENARIOS,
    TRUE_POSITIVE_SCENARIOS,
)


@pytest.fixture(scope="module")
def threat_prompt() -> str:
    """Load threat prompt using a dummy key (no network calls)."""
    analyzer = LLMAnalyzer(Config(llm_provider_api_key="test-api-key"))
    return analyzer._threat_analysis_prompt


def test_prompt_includes_regulated_data_guidance(threat_prompt: str) -> None:
    """Prompt documents PHI/PCI/PII rules and defensive exceptions."""
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
        assert needle in threat_prompt, f"Missing prompt guidance: {needle!r}"


def test_prompt_documents_false_positive_exceptions(threat_prompt: str) -> None:
    """Defensive and authorized-workflow exceptions are present."""
    for needle in (
        "audit PHI access",
        "scan for PCI compliance gaps",
        "lookup_patient_for_appointment",
        "submit_lab_order",
        "stripe_create_charge",
        "process_refund",
    ):
        assert needle in threat_prompt, f"Missing FP exception guidance: {needle!r}"


def test_false_positive_scenario_catalog_is_non_empty() -> None:
    assert len(FALSE_POSITIVE_SCENARIOS) >= 10
    assert len(TRUE_POSITIVE_SCENARIOS) >= 2
    categories = {s.category for s in FALSE_POSITIVE_SCENARIOS}
    assert "defensive_pii" in categories
    assert "authorized_payment" in categories
    assert "authorized_healthcare" in categories


@pytest.mark.parametrize(
    "name,description",
    [
        ("get_medical_data", "Returns medical data containing PHI violations"),
        ("get_payment_data", "Returns payment data containing PCI violations"),
    ],
)
def test_mock_mcp_true_positive_examples_in_prompt(
    threat_prompt: str, name: str, description: str
) -> None:
    assert description in threat_prompt
    assert name in threat_prompt
