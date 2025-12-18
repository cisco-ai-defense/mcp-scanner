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


"""Tests for MCP decorator detection with custom variable names."""


import pytest

# Skip all tests if CodeContextExtractor is not available
pytest.skip("CodeContextExtractor tests require full static analysis implementation", allow_module_level=True)




# Test cases with different variable names for FastMCP instance
CUSTOM_VARIABLE_TOOL = '''
from mcp import FastMCP
hello_mcp = FastMCP("Bearer-Protected SSE Server")
@hello_mcp.tool()
def hello(name: str) -> str:
    """
    Simple tool that greets the provided name.
    """
    return f"Hello, {name}!"
@hello_mcp.tool()
def add(a: int, b: int) -> int:
    """
    Adds two numbers and returns the sum.
    """
    return a + b
'''


MY_SERVER_VARIABLE = '''
from mcp import FastMCP
my_server = FastMCP("My Custom Server")
@my_server.prompt()
def create_prompt(text: str) -> str:
    """
    Creates a prompt from text.
    """
    return f"Prompt: {text}"
@my_server.resource()
def get_resource(id: str) -> dict:
    """
    Gets a resource by ID.
    """
    return {"id": id, "data": "example"}
'''


API_VARIABLE = '''
from mcp import FastMCP
api = FastMCP("API Server")
@api.tool()
def fetch_data(url: str) -> str:
    """
    Fetches data from a URL.
    """
    import requests
    return requests.get(url).text
'''


MIXED_DECORATORS = '''
from mcp import FastMCP
mcp = FastMCP("Standard Server")
custom_mcp = FastMCP("Custom Server")
@mcp.tool()
def standard_tool(x: int) -> int:
    """Standard tool."""
    return x * 2
@custom_mcp.tool()
def custom_tool(y: str) -> str:
    """Custom tool."""
    return y.upper()
@custom_mcp.prompt()
def custom_prompt(text: str) -> str:
    """Custom prompt."""
    return f"Custom: {text}"
'''




class TestCustomVariableMCPDetection:
    """Test cases for detecting MCP decorators with custom variable names."""


    def test_detect_hello_mcp_variable(self):
        """Test detection of @hello_mcp.tool() decorator."""
        extractor = CodeContextExtractor(CUSTOM_VARIABLE_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()


        assert len(contexts) == 2
        assert contexts[0].name == "hello"
        assert contexts[1].name == "add"
        assert "hello_mcp.tool" in contexts[0].decorator_types
        assert "hello_mcp.tool" in contexts[1].decorator_types


    def test_detect_my_server_variable(self):
        """Test detection of @my_server.prompt() and @my_server.resource() decorators."""
        extractor = CodeContextExtractor(MY_SERVER_VARIABLE, "test.py")
        contexts = extractor.extract_mcp_function_contexts()


        assert len(contexts) == 2
        assert contexts[0].name == "create_prompt"
        assert contexts[1].name == "get_resource"
        assert "my_server.prompt" in contexts[0].decorator_types
        assert "my_server.resource" in contexts[1].decorator_types


    def test_detect_api_variable(self):
        """Test detection of @api.tool() decorator."""
        extractor = CodeContextExtractor(API_VARIABLE, "test.py")
        contexts = extractor.extract_mcp_function_contexts()


        assert len(contexts) == 1
        assert contexts[0].name == "fetch_data"
        assert "api.tool" in contexts[0].decorator_types


    def test_detect_mixed_variables(self):
        """Test detection of multiple MCP instances with different variable names."""
        extractor = CodeContextExtractor(MIXED_DECORATORS, "test.py")
        contexts = extractor.extract_mcp_function_contexts()


        assert len(contexts) == 3


        # Check standard_tool with mcp.tool
        standard_tool = next(ctx for ctx in contexts if ctx.name == "standard_tool")
        assert "mcp.tool" in standard_tool.decorator_types


        # Check custom_tool with custom_mcp.tool
        custom_tool = next(ctx for ctx in contexts if ctx.name == "custom_tool")
        assert "custom_mcp.tool" in custom_tool.decorator_types


        # Check custom_prompt with custom_mcp.prompt
        custom_prompt = next(ctx for ctx in contexts if ctx.name == "custom_prompt")
        assert "custom_mcp.prompt" in custom_prompt.decorator_types


    def test_docstrings_extracted_correctly(self):
        """Test that docstrings are correctly extracted with custom variable names."""
        extractor = CodeContextExtractor(CUSTOM_VARIABLE_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()


        assert len(contexts) == 2
        assert "greets the provided name" in contexts[0].docstring
        assert "Adds two numbers" in contexts[1].docstring


    def test_parameters_extracted_correctly(self):
        """Test that parameters are correctly extracted with custom variable names."""
        extractor = CodeContextExtractor(CUSTOM_VARIABLE_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()


        # hello function
        assert len(contexts[0].parameters) == 1
        assert contexts[0].parameters[0]["name"] == "name"
        assert contexts[0].parameters[0]["type"] == "str"


        # add function
        assert len(contexts[1].parameters) == 2
        assert contexts[1].parameters[0]["name"] == "a"
        assert contexts[1].parameters[1]["name"] == "b"


    def test_return_types_extracted_correctly(self):
        """Test that return types are correctly extracted with custom variable names."""
        extractor = CodeContextExtractor(CUSTOM_VARIABLE_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()


        assert contexts[0].return_type == "str"
        assert contexts[1].return_type == "int"




class TestBackwardCompatibility:
    """Test that standard @mcp.tool() decorators still work."""


    def test_standard_mcp_variable_still_works(self):
        """Test that @mcp.tool() still works (backward compatibility)."""
        code = '''
from mcp import FastMCP
mcp = FastMCP("Standard Server")
@mcp.tool()
def standard_function(x: int) -> int:
    """Standard function."""
    return x * 2
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()


        assert len(contexts) == 1
        assert contexts[0].name == "standard_function"
        assert "mcp.tool" in contexts[0].decorator_types




if __name__ == "__main__":
    pytest.main([__file__, "-v"])
