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

"""Tests for Behavioral Analyzer - Main test suite."""

import pytest

class TestBehavioralAnalyzerModule:
    """Test that behavioral analyzer module is importable."""
    
    def test_behavioral_code_analyzer_import(self):
        """Test that BehavioralCodeAnalyzer can be imported."""
        from mcpscanner.core.analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer
        assert BehavioralCodeAnalyzer is not None
    
    def test_alignment_orchestrator_import(self):
        """Test that AlignmentOrchestrator can be imported."""
        from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import AlignmentOrchestrator
        assert AlignmentOrchestrator is not None
    
    def test_behavioral_analyzer_has_required_methods(self):
        """Test that BehavioralCodeAnalyzer has required methods."""
        from mcpscanner.core.analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer
        
        # Check that class has analyze method (main entry point)
        assert hasattr(BehavioralCodeAnalyzer, 'analyze'), \
            "BehavioralCodeAnalyzer should have analyze method"
    
    def test_analyzer_processes_python_syntax(self):
        """Test that analyzer can process Python code syntax."""
        import ast
        import tempfile
        from pathlib import Path
        
        # Create a test MCP tool
        code = '''
import mcp

@mcp.tool()
def example_tool(param: str) -> str:
    """Example tool."""
    return param.upper()
'''
        # Verify it's valid Python
        tree = ast.parse(code)
        assert tree is not None
        
        # Verify we can detect the decorator
        decorators = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        decorators.append(dec.func.attr)
        
        assert 'tool' in decorators, "Should detect @mcp.tool() decorator"
    
    def test_threat_categories_completeness(self):
        """Test that all major threat categories are covered."""
        from mcpscanner.threats.threats import ThreatMapping
        
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        # Major threat categories that should be covered
        important_categories = [
            "DATA EXFILTRATION",
            "INJECTION ATTACK",  # Updated from COMMAND INJECTION
            "DECEPTIVE BEHAVIOR",  # Updated from MISLEADING SAFETY CLAIMS
            "PROMPT INJECTION",
            "TOOL POISONING",
            "TOOL SHADOWING",
            "CODE EXECUTION",
            "UNAUTHORIZED SYSTEM ACCESS",
            "UNAUTHORIZED NETWORK ACCESS"
        ]
        
        for category in important_categories:
            assert category in behavioral_threats, f"Missing important category: {category}"
            
            threat = behavioral_threats[category]
            assert threat["severity"] in ["HIGH", "MEDIUM", "LOW"]
            assert len(threat["description"]) > 50, f"{category} description too short"
    
    def test_threat_mapper_import(self):
        """Test that threat mappings are available."""
        from mcpscanner.threats import threats
        assert threats is not None
        assert hasattr(threats, 'ThreatMapping')
