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


class TestPromptBuilder:
    """Test prompt building functionality."""
    
    def test_prompt_template_exists(self):
        """Test that prompt template file exists."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        assert prompt_path.exists(), "Prompt template file should exist"
    
    def test_prompt_template_not_empty(self):
        """Test that prompt template has content."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        content = prompt_path.read_text()
        assert len(content) > 0, "Prompt template should not be empty"
        assert "DATA EXFILTRATION" in content, "Prompt should contain threat definitions"
    
    def test_prompt_contains_all_threat_categories(self):
        """Test that prompt contains all behavioral threat categories."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        content = prompt_path.read_text()
        
        # Check for key threat categories mentioned in the prompt
        # Note: This prompt uses descriptive section titles for mismatch detection
        expected_threat_patterns = [
            "DATA EXFILTRATION",
            "COMMAND INJECTION",
            "mismatch",  # Core concept of this analyzer
        ]
        
        for threat_pattern in expected_threat_patterns:
            assert threat_pattern in content, f"Prompt should contain {threat_pattern} related content"
    
    def test_prompt_has_mismatch_detection_focus(self):
        """Test that prompt focuses on description mismatch detection."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        content = prompt_path.read_text()
        
        # Key concepts for mismatch detection
        keywords = ["mismatch", "docstring", "dataflow", "claims", "actual"]
        for keyword in keywords:
            assert keyword.lower() in content.lower(), f"Prompt should contain {keyword} concept"
    
    def test_prompt_length_adequate(self):
        """Test that prompt is sufficiently detailed."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        content = prompt_path.read_text()
        
        assert len(content) > 5000, f"Prompt seems too short: {len(content)} characters"
    
    def test_prompt_has_severity_levels(self):
        """Test that prompt defines severity levels."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        content = prompt_path.read_text()
        
        # Should define severity levels
        for severity in ["HIGH", "MEDIUM", "LOW"]:
            assert severity in content, f"Prompt should define {severity} severity"
    
    def test_prompt_has_json_format_instructions(self):
        """Test that prompt includes JSON response format instructions."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        content = prompt_path.read_text()
        
        # Should have JSON format instructions
        json_keywords = ["json", "{", "}"]
        for keyword in json_keywords:
            assert keyword.lower() in content.lower(), f"Prompt should contain JSON format keyword: {keyword}"
        
        # Check for response structure
        response_indicators = ["mismatch", "severity", "confidence"]
        found_count = sum(1 for indicator in response_indicators if indicator.lower() in content.lower())
        assert found_count >= 2, "Prompt should indicate expected response structure"
    
    def test_prompt_length_adequate(self):
        """Test that prompt is sufficiently detailed."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        content = prompt_path.read_text()
        
        # Prompt should be comprehensive (at least 5000 characters)
        assert len(content) > 5000, f"Prompt seems too short: {len(content)} characters"
    
    def test_prompt_has_example_cases(self):
        """Test that prompt includes example cases."""
        prompt_path = Path(__file__).parent.parent.parent / "mcpscanner" / "data" / "prompts" / "code_alignment_threat_analysis_prompt.md"
        content = prompt_path.read_text()
        
        # Should have examples
        example_keywords = ["example", "docstring", "actual behavior"]
        found_examples = sum(1 for kw in example_keywords if kw.lower() in content.lower())
        assert found_examples >= 2, "Prompt should contain example cases"
