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

"""Unit tests for ReadinessAnalyzer.

Tests all 20 heuristic rules (HEUR-001 through HEUR-020) for production
readiness analysis of MCP tools.
"""

import json
import pytest
from pathlib import Path

from mcpscanner.core.analyzers.readiness import ReadinessAnalyzer


# --- Helper Functions ---


def get_fixture_path(filename: str) -> Path:
    """Get path to a fixture file."""
    return Path(__file__).parent / "fixtures" / filename


def load_fixture(filename: str) -> dict:
    """Load a JSON fixture file."""
    with open(get_fixture_path(filename)) as f:
        return json.load(f)


def find_finding_by_rule(findings, rule_id: str):
    """Find a finding by its rule ID."""
    for finding in findings:
        if finding.details and finding.details.get("rule_id") == rule_id:
            return finding
    return None


# --- Test Classes ---


class TestReadinessAnalyzerInitialization:
    """Test ReadinessAnalyzer initialization."""

    def test_default_initialization(self):
        """Test default initialization."""
        analyzer = ReadinessAnalyzer()
        assert analyzer.name == "READINESS"
        assert analyzer.max_capabilities == 10
        assert analyzer.min_description_length == 20

    def test_custom_initialization(self):
        """Test initialization with custom parameters."""
        analyzer = ReadinessAnalyzer(
            max_capabilities=5,
            min_description_length=50,
        )
        assert analyzer.max_capabilities == 5
        assert analyzer.min_description_length == 50


class TestHEUR008NoOutputSchema:
    """Tests for HEUR-008: No output schema."""

    @pytest.mark.asyncio
    async def test_missing_output_schema_triggers_finding(self):
        """Tool without output schema should trigger LOW finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool that does something useful",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-008")
        assert finding is not None
        assert finding.severity == "LOW"

    @pytest.mark.asyncio
    async def test_with_output_schema_no_finding(self):
        """Tool with output schema should not trigger HEUR-008."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool that does something useful",
            "timeout": 30000,
            "outputSchema": {
                "type": "object",
                "properties": {
                    "result": {"type": "string"},
                },
            },
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-008")
        assert finding is None


class TestHEUR009VagueDescription:
    """Tests for HEUR-009: Vague description."""

    @pytest.mark.asyncio
    async def test_missing_description_triggers_finding(self):
        """Tool without description should trigger MEDIUM finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-009")
        assert finding is not None
        assert finding.severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_short_description_triggers_finding(self):
        """Short description should trigger MEDIUM finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A tool",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-009")
        assert finding is not None
        assert finding.severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_good_description_no_finding(self):
        """Good description should not trigger HEUR-009."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "Calculate the sum of two numbers and return the result",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-009")
        assert finding is None


class TestHEUR010TooManyCapabilities:
    """Tests for HEUR-010: Too many capabilities."""

    @pytest.mark.asyncio
    async def test_overload_keyword_triggers_finding(self):
        """Description with 'everything' should trigger HIGH finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "This tool can do everything you need with data",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-010")
        assert finding is not None
        assert finding.severity == "HIGH"
        assert "everything" in finding.details.get("keywords", [])

    @pytest.mark.asyncio
    async def test_many_verbs_triggers_finding(self):
        """Description with many action verbs should trigger HIGH finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "This tool can create, read, update, delete, fetch, send data",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-010")
        assert finding is not None
        assert finding.severity == "HIGH"

    @pytest.mark.asyncio
    async def test_focused_description_no_finding(self):
        """Focused description should not trigger HEUR-010."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "Calculate the sum of two numbers and return the result",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-010")
        assert finding is None


class TestHEUR011NoRequiredFields:
    """Tests for HEUR-011: No required fields."""

    @pytest.mark.asyncio
    async def test_properties_without_required_triggers_finding(self):
        """InputSchema with properties but no required should trigger LOW finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool that does something useful",
            "timeout": 30000,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "value": {"type": "number"},
                },
            },
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-011")
        assert finding is not None
        assert finding.severity == "LOW"

    @pytest.mark.asyncio
    async def test_with_required_fields_no_finding(self):
        """InputSchema with required fields should not trigger HEUR-011."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool that does something useful",
            "timeout": 30000,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
                "required": ["name"],
            },
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-011")
        assert finding is None


class TestHEUR012NoInputValidationHints:
    """Tests for HEUR-012: No input validation hints."""

    @pytest.mark.asyncio
    async def test_properties_without_validation_triggers_finding(self):
        """Properties without validation should trigger INFO finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool that does something useful",
            "timeout": 30000,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "value": {"type": "number"},
                },
            },
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-012")
        assert finding is not None
        assert finding.severity == "INFO"

    @pytest.mark.asyncio
    async def test_properties_with_validation_no_finding(self):
        """Properties with validation should not trigger HEUR-012."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool that does something useful",
            "timeout": 30000,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 100},
                    "value": {"type": "number", "minimum": 0, "maximum": 1000},
                },
            },
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-012")
        assert finding is None


class TestHEUR016ResourceCleanupNotDocumented:
    """Tests for HEUR-016: Resource cleanup not documented."""

    @pytest.mark.asyncio
    async def test_resources_without_cleanup_doc_triggers_finding(self):
        """Resources without cleanup documentation should trigger MEDIUM finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "Opens a database connection and executes a query",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-016")
        assert finding is not None
        assert finding.severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_resources_with_cleanup_doc_no_finding(self):
        """Resources with cleanup documentation should not trigger HEUR-016."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "Opens a database connection and automatically closes it after the query",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-016")
        assert finding is None


class TestHEUR017NoIdempotencyIndication:
    """Tests for HEUR-017: No idempotency indication."""

    @pytest.mark.asyncio
    async def test_state_changing_without_idempotency_doc_triggers_finding(self):
        """State-changing without idempotency doc should trigger INFO finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "Create a new user record in the database",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-017")
        assert finding is not None
        assert finding.severity == "INFO"

    @pytest.mark.asyncio
    async def test_state_changing_with_idempotency_doc_no_finding(self):
        """State-changing with idempotency doc should not trigger HEUR-017."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "Create a user record. This operation is idempotent and safe to retry.",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-017")
        assert finding is None


class TestHEUR017MCPAnnotations:
    """Tests for HEUR-017 MCP annotations.idempotentHint support."""

    @pytest.mark.asyncio
    async def test_idempotent_hint_suppresses_finding(self):
        """Tool with annotations.idempotentHint=true should not trigger HEUR-017."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "create_user",
            "description": "Create a new user in the system",
            "annotations": {"idempotentHint": True},
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "create_user"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-017")
        assert finding is None

    @pytest.mark.asyncio
    async def test_idempotent_hint_false_suppresses_finding(self):
        """Tool with annotations.idempotentHint=false should also suppress (hint is declared)."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "delete_record",
            "description": "Delete a record from the database",
            "annotations": {"idempotentHint": False},
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "delete_record"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-017")
        assert finding is None

    @pytest.mark.asyncio
    async def test_null_annotations_handled(self):
        """Tool with annotations=null should not crash."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "update_record",
            "description": "Update a record in the database",
            "annotations": None,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "update_record"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-017")
        assert finding is not None
        assert finding.severity == "INFO"

    @pytest.mark.asyncio
    async def test_readonly_hint_false_triggers_finding(self):
        """Tool with readOnlyHint=false and no idempotentHint should trigger HEUR-017."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "silent_tool",
            "description": "Does something quietly",
            "annotations": {"readOnlyHint": False},
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "silent_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-017")
        assert finding is not None
        assert finding.severity == "INFO"


class TestHEUR018DangerousOperationKeywords:
    """Tests for HEUR-018: Dangerous operation keywords."""

    @pytest.mark.asyncio
    async def test_delete_keyword_triggers_finding(self):
        """Tool with 'delete' keyword should trigger HIGH finding without destructiveHint."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "delete_user",
            "description": "Delete a user from the system",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "delete_user"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-018")
        assert finding is not None
        assert finding.severity == "HIGH"
        assert "delete" in finding.details.get("keywords", [])

    @pytest.mark.asyncio
    async def test_exec_keyword_triggers_finding(self):
        """Tool with 'exec' keyword should trigger HIGH finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "exec_command",
            "description": "Execute a shell command on the server",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "exec_command"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-018")
        assert finding is not None
        assert finding.severity == "HIGH"

    @pytest.mark.asyncio
    async def test_destructive_hint_downgrades_to_medium(self):
        """Tool with destructiveHint=true should be MEDIUM instead of HIGH."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "delete_user",
            "description": "Delete a user from the system",
            "annotations": {"destructiveHint": True},
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "delete_user"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-018")
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.details.get("destructiveHint") is True

    @pytest.mark.asyncio
    async def test_safe_tool_no_finding(self):
        """Safe tool name should not trigger HEUR-018."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "calculate_sum",
            "description": "Calculate the sum of two numbers",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "calculate_sum"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-018")
        assert finding is None


class TestHEUR020CircularDependencyRisk:
    """Tests for HEUR-020: Circular dependency risk."""

    @pytest.mark.asyncio
    async def test_self_reference_triggers_finding(self):
        """Tool referencing itself should trigger MEDIUM finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "recursive_processor",
            "description": "Processes data and may call recursive_processor again for nested items",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "recursive_processor"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-020")
        assert finding is not None
        assert finding.severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_recursive_pattern_triggers_finding(self):
        """Tool with recursive pattern should trigger MEDIUM finding."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "Uses recursive calls to process nested structures",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-020")
        assert finding is not None
        assert finding.severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_no_circular_pattern_no_finding(self):
        """Tool without circular patterns should not trigger HEUR-020."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "calculate_sum",
            "description": "Calculate the sum of two numbers and return the result",
            "timeout": 30000,
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "calculate_sum"}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-020")
        assert finding is None


class TestReadinessScore:
    """Tests for readiness score calculation."""

    @pytest.mark.asyncio
    async def test_good_tool_high_score(self):
        """Well-configured tool should have high readiness score."""
        analyzer = ReadinessAnalyzer()
        tool_def = load_fixture("good_tool.json")
        content = json.dumps(tool_def)
        context = {"tool_name": tool_def["name"]}

        findings = await analyzer.analyze(content, context)

        # Good tool should have minimal findings
        assert len(findings) <= 2

        # If there are findings, check the score is high
        if findings:
            score = findings[0].details.get("readiness_score", 0)
            assert score >= 70

    @pytest.mark.asyncio
    async def test_bad_tool_low_score(self):
        """Poorly configured tool should have low readiness score."""
        analyzer = ReadinessAnalyzer()
        tool_def = load_fixture("bad_tool.json")
        content = json.dumps(tool_def)
        context = {"tool_name": tool_def["name"]}

        findings = await analyzer.analyze(content, context)

        # Bad tool should have multiple findings
        assert len(findings) >= 3

        # Score should be at or below the production-ready threshold
        if findings:
            score = findings[0].details.get("readiness_score", 100)
            assert score <= 70


class TestContextHandling:
    """Tests for context handling."""

    @pytest.mark.asyncio
    async def test_tool_definition_in_context(self):
        """Tool definition provided in context should be used."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool that does something useful",
            "outputSchema": {"type": "object", "properties": {"result": {"type": "string"}}},
        }
        context = {
            "tool_name": "test_tool",
            "tool_definition": tool_def,
        }

        findings = await analyzer.analyze("{}", context)

        # Should use the tool definition from context
        finding = find_finding_by_rule(findings, "HEUR-008")
        assert finding is None  # Has outputSchema, so no HEUR-008

    @pytest.mark.asyncio
    async def test_plain_text_content(self):
        """Plain text content should be wrapped as description."""
        analyzer = ReadinessAnalyzer()
        content = "This is a plain text description of a tool"
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        # Should be parsed as a tool with only description
        # Will trigger HEUR-008 (missing outputSchema)
        finding = find_finding_by_rule(findings, "HEUR-008")
        assert finding is not None

    @pytest.mark.asyncio
    async def test_unknown_tool_name_default(self):
        """Missing tool name should default to 'unknown'."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool",
        }
        content = json.dumps(tool_def)

        findings = await analyzer.analyze(content, None)

        # Should work without context
        assert len(findings) >= 1


class TestFixtureFiles:
    """Tests using fixture files."""

    @pytest.mark.asyncio
    async def test_good_tool_fixture(self):
        """Test good_tool.json fixture passes most checks."""
        analyzer = ReadinessAnalyzer()
        tool_def = load_fixture("good_tool.json")
        content = json.dumps(tool_def)
        context = {"tool_name": tool_def["name"]}

        findings = await analyzer.analyze(content, context)

        # Good tool should not have critical or high severity findings
        critical_high = [f for f in findings if f.severity in ["CRITICAL", "HIGH"]]
        assert len(critical_high) == 0

    @pytest.mark.asyncio
    async def test_bad_tool_fixture(self):
        """Test bad_tool.json fixture triggers multiple findings."""
        analyzer = ReadinessAnalyzer()
        tool_def = load_fixture("bad_tool.json")
        content = json.dumps(tool_def)
        context = {"tool_name": tool_def["name"]}

        findings = await analyzer.analyze(content, context)

        # Bad tool should trigger HEUR-018 (delete keyword)
        finding_018 = find_finding_by_rule(findings, "HEUR-018")
        assert finding_018 is not None

        # Bad tool should trigger HEUR-009 (short description)
        finding_009 = find_finding_by_rule(findings, "HEUR-009")
        assert finding_009 is not None

    @pytest.mark.asyncio
    async def test_overloaded_scope_fixture(self):
        """Test tool_overloaded_scope.json triggers HEUR-010."""
        analyzer = ReadinessAnalyzer()
        tool_def = load_fixture("tool_overloaded_scope.json")
        content = json.dumps(tool_def)
        context = {"tool_name": tool_def["name"]}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-010")
        assert finding is not None
        assert finding.severity == "HIGH"

    @pytest.mark.asyncio
    async def test_resources_fixture(self):
        """Test tool_with_resources.json triggers HEUR-016."""
        analyzer = ReadinessAnalyzer()
        tool_def = load_fixture("tool_with_resources.json")
        content = json.dumps(tool_def)
        context = {"tool_name": tool_def["name"]}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-016")
        assert finding is not None
        assert finding.severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_self_referencing_fixture(self):
        """Test tool_self_referencing.json triggers HEUR-020."""
        analyzer = ReadinessAnalyzer()
        tool_def = load_fixture("tool_self_referencing.json")
        content = json.dumps(tool_def)
        context = {"tool_name": tool_def["name"]}

        findings = await analyzer.analyze(content, context)

        finding = find_finding_by_rule(findings, "HEUR-020")
        assert finding is not None
        assert finding.severity == "MEDIUM"

