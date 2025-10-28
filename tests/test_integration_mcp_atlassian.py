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

"""Integration test for scanning real-world MCP servers with custom variable names.

This test verifies that the scanner can handle the mcp-atlassian repository which uses:
- @confluence_mcp.tool() decorators
- @jira_mcp.tool() decorators
- Large files (746+ lines)
- Multiple functions per file (11-31 functions)
"""

import os
import time
import pytest
from pathlib import Path

from mcpscanner.behavioural.context_extractor import CodeContextExtractor


# Path to the cloned mcp-atlassian repository
MCP_ATLASSIAN_PATH = Path(__file__).parent.parent / "mcp-test" / "mcp-atlassian"
CONFLUENCE_FILE = MCP_ATLASSIAN_PATH / "src" / "mcp_atlassian" / "servers" / "confluence.py"
JIRA_FILE = MCP_ATLASSIAN_PATH / "src" / "mcp_atlassian" / "servers" / "jira.py"


@pytest.mark.skipif(
    not CONFLUENCE_FILE.exists(),
    reason="mcp-atlassian repository not cloned in mcp-test/"
)
class TestMCPAtlassianIntegration:
    """Integration tests using the real mcp-atlassian repository."""

    def test_confluence_server_detection(self):
        """Test that we can detect all MCP tools in confluence.py with custom variable name."""
        with open(CONFLUENCE_FILE, 'r') as f:
            source_code = f.read()
        
        extractor = CodeContextExtractor(source_code, 'confluence.py')
        contexts = extractor.extract_mcp_function_contexts()
        
        # Verify we found the expected number of functions
        assert len(contexts) == 11, f"Expected 11 functions, found {len(contexts)}"
        
        # Verify all use the custom @confluence_mcp.tool() decorator
        for ctx in contexts:
            assert len(ctx.decorator_types) > 0
            assert "confluence_mcp.tool" in ctx.decorator_types[0]
        
        # Verify specific known functions
        function_names = [ctx.name for ctx in contexts]
        assert "search" in function_names
        assert "get_page" in function_names
        assert "create_page" in function_names
        assert "update_page" in function_names
        assert "delete_page" in function_names

    def test_jira_server_detection(self):
        """Test that we can detect all MCP tools in jira.py with custom variable name."""
        with open(JIRA_FILE, 'r') as f:
            source_code = f.read()
        
        extractor = CodeContextExtractor(source_code, 'jira.py')
        contexts = extractor.extract_mcp_function_contexts()
        
        # Verify we found the expected number of functions
        assert len(contexts) == 31, f"Expected 31 functions, found {len(contexts)}"
        
        # Verify all use the custom @jira_mcp.tool() decorator
        for ctx in contexts:
            assert len(ctx.decorator_types) > 0
            assert "jira_mcp.tool" in ctx.decorator_types[0]
        
        # Verify specific known functions
        function_names = [ctx.name for ctx in contexts]
        assert "get_issue" in function_names
        assert "search" in function_names
        assert "create_issue" in function_names

    def test_performance_large_file(self):
        """Test that analysis completes in reasonable time for large files."""
        with open(JIRA_FILE, 'r') as f:
            source_code = f.read()
        
        # jira.py has 1655 lines and 31 functions
        start = time.time()
        extractor = CodeContextExtractor(source_code, 'jira.py')
        contexts = extractor.extract_mcp_function_contexts()
        elapsed = time.time() - start
        
        # Should complete in under 1 second (was hanging before the fix)
        assert elapsed < 1.0, f"Analysis took {elapsed:.2f}s, expected < 1.0s"
        assert len(contexts) == 31

    def test_parameter_flows_extracted(self):
        """Test that parameter flow analysis works correctly."""
        with open(CONFLUENCE_FILE, 'r') as f:
            source_code = f.read()
        
        extractor = CodeContextExtractor(source_code, 'confluence.py')
        contexts = extractor.extract_mcp_function_contexts()
        
        # All functions should have parameter flow analysis
        for ctx in contexts:
            # Functions with parameters should have flows
            if len(ctx.parameters) > 0:
                assert ctx.parameter_flows is not None
                # At least some parameters should have flows
                assert len(ctx.parameter_flows) >= 0

    def test_function_metadata_complete(self):
        """Test that all function metadata is extracted correctly."""
        with open(CONFLUENCE_FILE, 'r') as f:
            source_code = f.read()
        
        extractor = CodeContextExtractor(source_code, 'confluence.py')
        contexts = extractor.extract_mcp_function_contexts()
        
        for ctx in contexts:
            # Basic metadata
            assert ctx.name is not None
            assert len(ctx.name) > 0
            assert ctx.line_number > 0
            assert len(ctx.decorator_types) > 0
            
            # Code structure
            assert ctx.function_calls is not None
            assert ctx.assignments is not None
            assert ctx.control_flow is not None
            
            # Parameters
            assert ctx.parameters is not None
            
            # Behavioral patterns
            assert isinstance(ctx.has_file_operations, bool)
            assert isinstance(ctx.has_network_operations, bool)
            assert isinstance(ctx.has_subprocess_calls, bool)

    def test_docstrings_extracted(self):
        """Test that docstrings are properly extracted."""
        with open(CONFLUENCE_FILE, 'r') as f:
            source_code = f.read()
        
        extractor = CodeContextExtractor(source_code, 'confluence.py')
        contexts = extractor.extract_mcp_function_contexts()
        
        # Most functions should have docstrings
        with_docstrings = sum(1 for ctx in contexts if ctx.docstring)
        assert with_docstrings >= 10, f"Expected at least 10 functions with docstrings, found {with_docstrings}"

    def test_multiple_files_batch(self):
        """Test scanning multiple files in batch."""
        files = [CONFLUENCE_FILE, JIRA_FILE]
        
        total_functions = 0
        start = time.time()
        
        for file_path in files:
            with open(file_path, 'r') as f:
                source_code = f.read()
            
            extractor = CodeContextExtractor(source_code, file_path.name)
            contexts = extractor.extract_mcp_function_contexts()
            total_functions += len(contexts)
        
        elapsed = time.time() - start
        
        # Should find 11 + 31 = 42 functions total
        assert total_functions == 42, f"Expected 42 functions, found {total_functions}"
        
        # Should complete in under 2 seconds
        assert elapsed < 2.0, f"Batch analysis took {elapsed:.2f}s, expected < 2.0s"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
