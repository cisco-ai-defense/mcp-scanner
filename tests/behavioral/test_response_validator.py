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

"""Tests for AlignmentResponseValidator component."""

import pytest
from unittest.mock import MagicMock

from mcpscanner.core.analyzers.behavioral.alignment.alignment_response_validator import (
    AlignmentResponseValidator,
)
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.threats.threats import ThreatMapping


class TestResponseValidator:
    """Test response validation functionality."""

    def test_validator_module_exists(self):
        """Test that response validator module exists."""
        try:
            from mcpscanner.core.analyzers.behavioral.alignment import (
                alignment_response_validator,
            )

            assert alignment_response_validator is not None
        except ImportError:
            pytest.skip("Response validator module structure needs verification")


class TestResponseValidatorSeverityFromThreatMapping:
    """Test that create_security_finding uses severity from ThreatMapping."""

    def _make_func_context(self, name="test_func", line_number=10):
        """Create a mock FunctionContext."""
        ctx = MagicMock()
        ctx.name = name
        ctx.line_number = line_number
        ctx.decorator_types = ["tool"]
        ctx.parameter_flows = {}
        return ctx

    def _make_validator(self):
        """Create an AlignmentResponseValidator."""
        return AlignmentResponseValidator()

    def test_severity_from_threat_mapping_data_exfiltration(self):
        """Test that DATA EXFILTRATION gets severity from ThreatMapping (HIGH)."""
        validator = self._make_validator()
        analysis = {
            "threat_name": "DATA EXFILTRATION",
            "description_claims": "Reads a local file",
            "actual_behavior": "Sends data to external server",
            "security_implications": "Data exfiltration detected",
        }
        func_context = self._make_func_context()

        finding = validator.create_security_finding(analysis, func_context)

        expected_severity = ThreatMapping.get_threat_mapping(
            "behavioral", "DATA EXFILTRATION"
        )["severity"]
        assert finding.severity == expected_severity
        assert finding.severity == "HIGH"
        assert isinstance(finding, SecurityFinding)

    def test_severity_from_threat_mapping_tool_poisoning(self):
        """Test that TOOL POISONING gets severity from ThreatMapping (HIGH)."""
        validator = self._make_validator()
        analysis = {
            "threat_name": "TOOL POISONING",
            "description_claims": "Adds two numbers",
            "actual_behavior": "Reads config files secretly",
            "security_implications": "Hidden instructions in docstring",
        }
        func_context = self._make_func_context()

        finding = validator.create_security_finding(analysis, func_context)

        expected_severity = ThreatMapping.get_threat_mapping(
            "behavioral", "TOOL POISONING"
        )["severity"]
        assert finding.severity == expected_severity
        assert finding.severity == "HIGH"

    def test_severity_from_threat_mapping_general_mismatch(self):
        """Test that GENERAL DESCRIPTION-CODE MISMATCH gets severity from ThreatMapping (INFO)."""
        validator = self._make_validator()
        analysis = {
            "threat_name": "GENERAL DESCRIPTION-CODE MISMATCH",
            "description_claims": "No docstring provided",
            "actual_behavior": "Safe string formatting",
            "security_implications": "Missing documentation only",
        }
        func_context = self._make_func_context()

        finding = validator.create_security_finding(analysis, func_context)

        expected_severity = ThreatMapping.get_threat_mapping(
            "behavioral", "GENERAL DESCRIPTION-CODE MISMATCH"
        )["severity"]
        assert finding.severity == expected_severity
        assert finding.severity == "INFO"

    def test_severity_unknown_for_unrecognized_threat(self):
        """Test that unrecognized threat names get UNKNOWN severity."""
        validator = self._make_validator()
        analysis = {
            "threat_name": "NONEXISTENT THREAT TYPE",
            "description_claims": "Some claims",
            "actual_behavior": "Some behavior",
            "security_implications": "Some implications",
        }
        func_context = self._make_func_context()

        finding = validator.create_security_finding(analysis, func_context)

        assert finding.severity == "UNKNOWN"

    def test_severity_unknown_for_empty_threat_name(self):
        """Test that empty threat name gets UNKNOWN severity."""
        validator = self._make_validator()
        analysis = {
            "description_claims": "Some claims",
            "actual_behavior": "Some behavior",
        }
        func_context = self._make_func_context()

        finding = validator.create_security_finding(analysis, func_context)

        assert finding.severity == "UNKNOWN"

    def test_severity_always_from_threat_mapping(self):
        """Test that severity always comes from ThreatMapping, not the analysis dict."""
        validator = self._make_validator()
        analysis = {
            "threat_name": "DATA EXFILTRATION",
            "description_claims": "Reads a local file",
            "actual_behavior": "Sends data to external server",
            "security_implications": "Data exfiltration detected",
        }
        func_context = self._make_func_context()

        finding = validator.create_security_finding(analysis, func_context)

        # DATA EXFILTRATION severity is HIGH in threats.py BEHAVIORAL_THREATS
        assert finding.severity == "HIGH"


class TestFindingClassContract:
    """The alignment prompt declares which class a finding belongs to.

    Reachability findings (an MCP parameter reaching a shell) must stay
    distinguishable from intent findings (a deliberately hidden backdoor),
    so a consumer can treat an honest-but-dangerous tool differently from
    a malicious one.
    """

    def _make_func_context(self):
        ctx = MagicMock()
        ctx.name = "test_func"
        ctx.line_number = 10
        ctx.decorator_types = ["tool"]
        ctx.parameter_flows = {}
        return ctx

    @pytest.mark.parametrize(
        "declared,expected",
        [
            ("MALICIOUS_BEHAVIOR", "MALICIOUS_BEHAVIOR"),
            ("CAPABILITY_RISK", "CAPABILITY_RISK"),
            ("DOCUMENTATION_MISMATCH", "DOCUMENTATION_MISMATCH"),
            ("capability risk", "CAPABILITY_RISK"),
            ("Malicious-Behavior", "MALICIOUS_BEHAVIOR"),
        ],
    )
    def test_declared_classes_are_preserved(self, declared, expected):
        finding = AlignmentResponseValidator().create_security_finding(
            {
                "threat_name": "INJECTION ATTACKS",
                "summary": "x",
                "finding_class": declared,
            },
            self._make_func_context(),
        )
        assert finding.details["finding_class"] == expected

    @pytest.mark.parametrize("bogus", [None, "", "SAFE", "TOTALLY_FINE", 42, {}])
    def test_unknown_or_missing_class_is_unspecified(self, bogus):
        """A missing declaration must not be upgraded into a claim of intent."""
        analysis = {"threat_name": "INJECTION ATTACKS", "summary": "x"}
        if bogus is not None:
            analysis["finding_class"] = bogus

        finding = AlignmentResponseValidator().create_security_finding(
            analysis, self._make_func_context()
        )
        assert finding.details["finding_class"] == "UNSPECIFIED"

    def test_finding_class_does_not_affect_severity(self):
        """Severity stays owned by ThreatMapping, not by the model's class."""
        ctx = self._make_func_context()
        validator = AlignmentResponseValidator()
        base = {"threat_name": "DATA EXFILTRATION", "summary": "x"}

        malicious = validator.create_security_finding(
            {**base, "finding_class": "MALICIOUS_BEHAVIOR"}, ctx
        )
        capability = validator.create_security_finding(
            {**base, "finding_class": "CAPABILITY_RISK"}, ctx
        )
        assert malicious.severity == capability.severity == "HIGH"
