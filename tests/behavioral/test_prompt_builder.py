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

"""Tests for AlignmentPromptBuilder component."""

import pytest
from pathlib import Path

from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.analyzers.behavioral.alignment.alignment_prompt_builder import (
    AlignmentPromptBuilder,
    _ANALYSIS_TRUNCATION_SUFFIX,
    _TEMPLATE_TRUNCATION_SUFFIX,
)
from mcpscanner.core.static_analysis.context_extractor import FunctionContext


def _minimal_function_context(**overrides):
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


class TestAlignmentPromptBudget:
    """Alignment prompts must honor ALIGNMENT_MAX_PROMPT_CHARS end-to-end."""

    def test_assembled_prompt_respects_default_alignment_cap(self):
        builder = AlignmentPromptBuilder()
        cap = MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS
        huge_analysis = "X" * (cap + 10_000)
        prompt = builder._assemble_prompt(
            template=builder._template,
            analysis_content=huge_analysis,
            start_tag="<!---UNTRUSTED_INPUT_START_test--->",
            end_tag="<!---UNTRUSTED_INPUT_END_test--->",
            log_label="test=huge_analysis",
        )
        assert len(prompt) <= cap

    def test_template_truncated_when_fixed_overhead_exceeds_cap(self, monkeypatch):
        monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_MAX_PROMPT_CHARS", 8000)
        builder = AlignmentPromptBuilder()
        prompt = builder._assemble_prompt(
            template=builder._template,
            analysis_content="short body",
            start_tag="<!---UNTRUSTED_INPUT_START_test--->",
            end_tag="<!---UNTRUSTED_INPUT_END_test--->",
            log_label="test=template_cap",
        )
        assert _TEMPLATE_TRUNCATION_SUFFIX.strip() in prompt
        assert "## Required Output Format" in prompt
        assert '"mismatch_detected"' in prompt
        assert len(prompt) <= 8000

    def test_build_prompt_respects_alignment_cap(self):
        builder = AlignmentPromptBuilder()
        cap = MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS
        ctx = _minimal_function_context(docstring="D" * 50_000)
        prompt = builder.build_prompt(ctx)
        assert len(prompt) <= cap

    def test_analysis_truncation_includes_reserved_suffix(self):
        builder = AlignmentPromptBuilder()
        cap = MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS
        prompt = builder._assemble_prompt(
            template="T" * 1000,
            analysis_content="A" * cap,
            start_tag="<!---UNTRUSTED_INPUT_START_test--->",
            end_tag="<!---UNTRUSTED_INPUT_END_test--->",
            log_label="test=analysis_suffix",
        )
        assert _ANALYSIS_TRUNCATION_SUFFIX in prompt
        assert len(prompt) <= cap

    def test_graph_evidence_preserved_when_analysis_truncated(self, monkeypatch):
        monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_MAX_PROMPT_CHARS", 2500)
        builder = AlignmentPromptBuilder()
        graph_marker = "**CODE GRAPH EVIDENCE (deterministic static analysis):**"
        graph_body = "SINK: os.remove at line 42"
        analysis = (
            "F" * 8000
            + "\n**CODE GRAPH EVIDENCE (deterministic static analysis):**\n"
            + graph_body
            + "\n"
        )
        prompt = builder._assemble_prompt(
            template="T" * 800,
            analysis_content=analysis,
            start_tag="<!---UNTRUSTED_INPUT_START_test--->",
            end_tag="<!---UNTRUSTED_INPUT_END_test--->",
            log_label="test=graph_preserve",
        )
        assert graph_marker in prompt
        assert graph_body in prompt
        assert len(prompt) <= 2500

    def test_sink_hints_preserved_when_analysis_truncated(self, monkeypatch):
        monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_MAX_PROMPT_CHARS", 3000)
        builder = AlignmentPromptBuilder()
        sink_marker = "**CODE GRAPH SINK HINTS (deterministic, verify against docstring):**"
        sink_body = '"sink_name": "os.remove"'
        analysis = (
            "M" * 10_000
            + "\n**CODE GRAPH SINK HINTS (deterministic, verify against docstring):**\n"
            + f"[{sink_body}]\n"
        )
        prompt = builder._assemble_prompt(
            template="T" * 900,
            analysis_content=analysis,
            start_tag="<!---UNTRUSTED_INPUT_START_test--->",
            end_tag="<!---UNTRUSTED_INPUT_END_test--->",
            log_label="test=sink_hints_preserve",
        )
        assert sink_marker in prompt
        assert sink_body in prompt
        assert len(prompt) <= 3000

    def test_default_cap_preserves_graph_with_real_template(self):
        builder = AlignmentPromptBuilder()
        graph_body = "SINK ANALYSIS (deterministic):\n  os.remove"
        ctx = _minimal_function_context(
            dataflow_summary={
                "code_graph_evidence": graph_body,
                "code_graph_sink_hints": [
                    {"sink_name": "os.remove", "category": "file"}
                ],
            }
        )
        prompt = builder.build_prompt(ctx)
        cap = MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS
        assert len(prompt) <= cap
        assert "**CODE GRAPH EVIDENCE (deterministic static analysis):**" in prompt
        assert graph_body in prompt
        assert "**CODE GRAPH SINK HINTS" in prompt
        assert "os.remove" in prompt

    def test_pinned_response_schema_survives_guidance_truncation(self, monkeypatch):
        monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_MAX_PROMPT_CHARS", 12000)
        builder = AlignmentPromptBuilder()
        prompt = builder.build_prompt(
            _minimal_function_context(
                dataflow_summary={"code_graph_evidence": "SINK: os.remove"}
            )
        )
        assert "## Required Output Format" in prompt
        assert '"mismatch_detected"' in prompt
        assert '"threat_name"' in prompt
        assert '"summary"' in prompt
        assert len(prompt) <= 12000


class TestPromptBuilder:
    """Test prompt building functionality."""

    def test_prompt_template_exists(self):
        """Test that prompt template file exists."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        assert prompt_path.exists(), "Prompt template file should exist"

    def test_prompt_template_not_empty(self):
        """Test that prompt template has content."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        content = prompt_path.read_text()
        assert len(content) > 0, "Prompt template should not be empty"
        assert (
            "DATA EXFILTRATION" in content
        ), "Prompt should contain threat definitions"

    def test_prompt_contains_all_threat_categories(self):
        """Test that prompt contains all behavioral threat categories."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        content = prompt_path.read_text()

        # Check for key threat categories mentioned in the prompt
        # Note: This prompt uses descriptive section titles for mismatch detection
        expected_threat_patterns = [
            "DATA EXFILTRATION",
            "INJECTION ATTACKS",  # Updated from "COMMAND INJECTION" to match new prompt structure
            "mismatch",  # Core concept of this analyzer
        ]

        for threat_pattern in expected_threat_patterns:
            assert (
                threat_pattern in content
            ), f"Prompt should contain {threat_pattern} related content"

    def test_prompt_has_mismatch_detection_focus(self):
        """Test that prompt focuses on description mismatch detection."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        content = prompt_path.read_text()

        # Key concepts for mismatch detection
        keywords = ["mismatch", "docstring", "dataflow", "claims", "actual"]
        for keyword in keywords:
            assert (
                keyword.lower() in content.lower()
            ), f"Prompt should contain {keyword} concept"

    def test_prompt_length_adequate(self):
        """Test that prompt is sufficiently detailed."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        content = prompt_path.read_text()

        assert len(content) > 5000, f"Prompt seems too short: {len(content)} characters"

    def test_prompt_has_threat_categories(self):
        """Test that prompt defines threat categories."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        content = prompt_path.read_text()

        # Should define threat categories (severity is in threats.py, not in the prompt)
        for threat in ["PROMPT INJECTION", "DATA EXFILTRATION", "TOOL POISONING"]:
            assert threat in content, f"Prompt should define {threat} threat category"

    def test_prompt_has_json_format_instructions(self):
        """Test that prompt includes JSON response format instructions."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        content = prompt_path.read_text()

        # Should have JSON format instructions
        json_keywords = ["json", "{", "}"]
        for keyword in json_keywords:
            assert (
                keyword.lower() in content.lower()
            ), f"Prompt should contain JSON format keyword: {keyword}"

        # Check for response structure
        response_indicators = ["mismatch", "threat_name", "summary"]
        found_count = sum(
            1
            for indicator in response_indicators
            if indicator.lower() in content.lower()
        )
        assert found_count >= 2, "Prompt should indicate expected response structure"

    def test_prompt_length_adequate(self):
        """Test that prompt is sufficiently detailed."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        content = prompt_path.read_text()

        # Prompt should be comprehensive (at least 5000 characters)
        assert len(content) > 5000, f"Prompt seems too short: {len(content)} characters"

    def test_prompt_has_example_cases(self):
        """Test that prompt includes example cases."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / "mcpscanner"
            / "data"
            / "prompts"
            / "code_alignment_threat_analysis_prompt.md"
        )
        content = prompt_path.read_text()

        # Should have examples
        example_keywords = ["example", "docstring", "actual behavior"]
        found_examples = sum(
            1 for kw in example_keywords if kw.lower() in content.lower()
        )
        assert found_examples >= 2, "Prompt should contain example cases"


class TestBatchGraphEvidence:
    def test_batch_prompt_includes_code_graph_evidence(self):
        builder = AlignmentPromptBuilder()
        evidence = "CODE GRAPH SLICE (deterministic static analysis)\nEntry: foo"
        ctx = _minimal_function_context(
            name="tool_a",
            dataflow_summary={"code_graph_evidence": evidence},
        )
        batch_body = builder.build_batch_analysis_content([ctx])
        assert "CODE GRAPH EVIDENCE" in batch_body
        assert evidence in batch_body

    def test_single_and_batch_graph_sections_match(self):
        builder = AlignmentPromptBuilder()
        evidence = "SINK ANALYSIS (deterministic):\n  os.system"
        ctx = _minimal_function_context(
            dataflow_summary={"code_graph_evidence": evidence},
        )
        single_section = builder._format_graph_evidence_section(ctx)
        batch_body = builder.build_batch_analysis_content([ctx])
        assert single_section.strip() in batch_body

    def test_batch_assembled_prompt_keeps_graph_evidence_with_function(
        self, monkeypatch
    ):
        from mcpscanner.config.constants import MCPScannerConstants

        monkeypatch.setattr(
            MCPScannerConstants, "ALIGNMENT_MAX_PROMPT_CHARS", 500_000
        )
        builder = AlignmentPromptBuilder()
        evidence_a = "SINK ANALYSIS (deterministic):\n  os.system in tool_a"
        evidence_b = "SINK ANALYSIS (deterministic):\n  subprocess.run in tool_b"
        ctx_a = _minimal_function_context(
            name="tool_a",
            dataflow_summary={"code_graph_evidence": evidence_a},
        )
        ctx_b = _minimal_function_context(
            name="tool_b",
            dataflow_summary={"code_graph_evidence": evidence_b},
        )
        batch_body = builder.build_batch_analysis_content([ctx_a, ctx_b])
        prompt = builder.wrap_batch_prompt([ctx_a, ctx_b], batch_body)
        pos_a = prompt.find("=== FUNCTION 1 of 2 ===")
        pos_b = prompt.find("=== FUNCTION 2 of 2 ===")
        pos_evidence_a = prompt.find(evidence_a)
        pos_evidence_b = prompt.find(evidence_b)
        assert pos_a != -1 and pos_b != -1
        assert pos_evidence_a != -1 and pos_evidence_b != -1
        assert pos_a < pos_evidence_a < pos_b < pos_evidence_b
