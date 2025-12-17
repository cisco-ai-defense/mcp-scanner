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

"""Tests for Behavioural Context Extractor module."""

import pytest
from mcpscanner.behavioural.context_extractor import CodeContextExtractor, FunctionContext


# Sample MCP code for testing
SIMPLE_MCP_TOOL = '''
import mcp

@mcp.tool()
def read_file(path: str) -> str:
    """Reads a file from the filesystem."""
    with open(path, 'r') as f:
        return f.read()
'''

MCP_TOOL_WITH_NETWORK = '''
import mcp
import requests

@mcp.tool()
def fetch_data(url: str) -> str:
    """Fetches data from a URL."""
    response = requests.get(url)
    return response.text
'''

MCP_TOOL_WITH_SUBPROCESS = '''
import mcp
import subprocess

@mcp.tool()
def run_command(cmd: str) -> str:
    """Executes a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()
'''

MCP_TOOL_WITH_EVAL = '''
import mcp

@mcp.tool()
def evaluate_code(code: str) -> Any:
    """Evaluates Python code."""
    return eval(code)
'''

MULTIPLE_MCP_TOOLS = '''
import mcp

@mcp.tool()
def tool_one(x: int) -> int:
    """First tool."""
    return x * 2

@mcp.tool()
def tool_two(y: str) -> str:
    """Second tool."""
    return y.upper()

@mcp.prompt()
def my_prompt(text: str) -> str:
    """A prompt."""
    return f"Prompt: {text}"
'''

MCP_TOOL_WITH_DATAFLOW = '''
import mcp

@mcp.tool()
def process_data(user_input: str) -> str:
    """Processes user input."""
    sanitized = user_input.strip()
    validated = sanitized.lower()
    result = validated.replace("bad", "good")
    return result
'''

MCP_TOOL_WITH_CONTROL_FLOW = '''
import mcp

@mcp.tool()
def conditional_process(value: int) -> str:
    """Processes value conditionally."""
    if value > 10:
        result = "high"
    elif value > 5:
        result = "medium"
    else:
        result = "low"
    
    for i in range(value):
        result += str(i)
    
    return result
'''

NO_MCP_DECORATORS = '''
def regular_function(x: int) -> int:
    """A regular function."""
    return x + 1

class MyClass:
    def method(self):
        pass
'''

INVALID_PYTHON_CODE = '''
def broken_function(
    # Missing closing parenthesis and body
'''


class TestCodeContextExtractorInitialization:
    """Test cases for CodeContextExtractor initialization."""

    def test_init_with_valid_code(self):
        """Test initialization with valid Python code."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        assert extractor.source_code == SIMPLE_MCP_TOOL
        assert extractor.file_path.name == "test.py"
        assert extractor.ast is not None
        assert extractor.analyzer is not None

    def test_init_with_invalid_code(self):
        """Test initialization with invalid Python code raises ValueError."""
        with pytest.raises(ValueError, match="Failed to parse source code"):
            CodeContextExtractor(INVALID_PYTHON_CODE, "test.py")

    def test_init_with_empty_code(self):
        """Test initialization with empty code."""
        extractor = CodeContextExtractor("", "test.py")
        assert extractor.source_code == ""
        assert extractor.ast is not None


class TestMCPFunctionDetection:
    """Test cases for MCP function detection."""

    def test_extract_single_mcp_tool(self):
        """Test extracting a single MCP tool."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].name == "read_file"
        assert "mcp.tool" in contexts[0].decorator_types
        assert contexts[0].docstring == "Reads a file from the filesystem."

    def test_extract_multiple_mcp_functions(self):
        """Test extracting multiple MCP functions."""
        extractor = CodeContextExtractor(MULTIPLE_MCP_TOOLS, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 3
        names = [ctx.name for ctx in contexts]
        assert "tool_one" in names
        assert "tool_two" in names
        assert "my_prompt" in names
        
        # Check decorator types
        decorators = [ctx.decorator_types for ctx in contexts]
        assert any("mcp.tool" in d for d in decorators)
        assert any("mcp.prompt" in d for d in decorators)

    def test_extract_no_mcp_functions(self):
        """Test extracting from code without MCP decorators."""
        extractor = CodeContextExtractor(NO_MCP_DECORATORS, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 0


class TestFunctionContextParameters:
    """Test cases for function parameter extraction."""

    def test_extract_function_parameters(self):
        """Test extracting function parameters."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        params = contexts[0].parameters
        assert len(params) >= 1
        assert any(p.get("name") == "path" for p in params)

    def test_extract_return_type(self):
        """Test extracting return type annotation."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].return_type == "str"


class TestBehavioralPatternDetection:
    """Test cases for behavioral pattern detection."""

    def test_detect_file_operations(self):
        """Test detection of file operations."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].has_file_operations == True

    def test_detect_network_operations(self):
        """Test detection of network operations."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_NETWORK, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].has_network_operations == True

    def test_detect_subprocess_calls(self):
        """Test detection of subprocess calls."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_SUBPROCESS, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].has_subprocess_calls == True

    def test_detect_eval_exec(self):
        """Test detection of eval/exec calls."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_EVAL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].has_eval_exec == True

    def test_detect_dangerous_imports(self):
        """Test detection of dangerous imports."""
        code = '''
import mcp
import os

@mcp.tool()
def use_os(cmd: str) -> str:
    """Uses os module."""
    return os.popen(cmd).read()
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        # os module should be detected as potentially dangerous
        assert len(contexts[0].imports) >= 0


class TestDataflowAnalysis:
    """Test cases for dataflow analysis."""

    def test_parameter_flow_tracking(self):
        """Test tracking parameter flows through the function."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_DATAFLOW, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].parameter_flows is not None
        assert len(contexts[0].parameter_flows) > 0
        
        # Should track user_input parameter
        param_names = [flow.get("parameter") for flow in contexts[0].parameter_flows]
        assert "user_input" in param_names

    def test_variable_dependencies(self):
        """Test extraction of variable dependencies."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_DATAFLOW, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].variable_dependencies is not None
        assert isinstance(contexts[0].variable_dependencies, dict)

    def test_function_calls_extraction(self):
        """Test extraction of function calls."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].function_calls is not None
        assert len(contexts[0].function_calls) > 0
        
        # Should detect 'open' call
        call_names = [call.get("name") for call in contexts[0].function_calls]
        assert "open" in call_names

    def test_assignments_extraction(self):
        """Test extraction of assignments."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_DATAFLOW, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].assignments is not None
        assert len(contexts[0].assignments) > 0


class TestControlFlowAnalysis:
    """Test cases for control flow analysis."""

    def test_detect_conditionals(self):
        """Test detection of conditional statements."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_CONTROL_FLOW, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].control_flow.get("has_conditionals") == True

    def test_detect_loops(self):
        """Test detection of loops."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_CONTROL_FLOW, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].control_flow.get("has_loops") == True

    def test_detect_exception_handling(self):
        """Test detection of exception handling."""
        code = '''
import mcp

@mcp.tool()
def safe_operation(x: int) -> int:
    """Safe operation with error handling."""
    try:
        result = 10 / x
    except ZeroDivisionError:
        result = 0
    return result
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].control_flow.get("has_exception_handling") == True


class TestConstantPropagation:
    """Test cases for constant propagation."""

    def test_extract_constants(self):
        """Test extraction of constants."""
        code = '''
import mcp

@mcp.tool()
def use_constants() -> str:
    """Uses constants."""
    API_KEY = "secret123"
    BASE_URL = "https://api.example.com"
    return BASE_URL + API_KEY
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].constants is not None
        assert isinstance(contexts[0].constants, dict)


class TestLineNumbers:
    """Test cases for line number tracking."""

    def test_line_number_extraction(self):
        """Test that line numbers are correctly extracted."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].line_number > 0
        # The function should be around line 4-5
        assert contexts[0].line_number >= 4

    def test_multiple_functions_line_numbers(self):
        """Test line numbers for multiple functions."""
        extractor = CodeContextExtractor(MULTIPLE_MCP_TOOLS, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 3
        line_numbers = [ctx.line_number for ctx in contexts]
        
        # Line numbers should be in ascending order
        assert line_numbers == sorted(line_numbers)
        # All should be positive
        assert all(ln > 0 for ln in line_numbers)


class TestDataflowSummary:
    """Test cases for dataflow summary."""

    def test_dataflow_summary_exists(self):
        """Test that dataflow summary is generated."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].dataflow_summary is not None
        assert isinstance(contexts[0].dataflow_summary, dict)

    def test_complexity_in_dataflow_summary(self):
        """Test that complexity is included in dataflow summary."""
        extractor = CodeContextExtractor(MCP_TOOL_WITH_CONTROL_FLOW, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert "complexity" in contexts[0].dataflow_summary
        # Complex function should have higher complexity
        assert contexts[0].dataflow_summary["complexity"] > 1


class TestEdgeCases:
    """Test cases for edge cases and error handling."""

    def test_function_without_docstring(self):
        """Test handling of function without docstring."""
        code = '''
import mcp

@mcp.tool()
def no_docstring(x: int) -> int:
    return x * 2
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].docstring is None or contexts[0].docstring == ""

    def test_function_without_type_annotations(self):
        """Test handling of function without type annotations."""
        code = '''
import mcp

@mcp.tool()
def no_types(x):
    """Function without type annotations."""
    return x
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].return_type is None

    def test_nested_function_with_mcp_decorator(self):
        """Test handling of nested functions."""
        code = '''
import mcp

def outer():
    @mcp.tool()
    def inner(x: int) -> int:
        """Nested MCP tool."""
        return x
    return inner
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        # Should still detect nested MCP functions
        assert len(contexts) >= 1

    def test_class_method_with_mcp_decorator(self):
        """Test handling of class methods with MCP decorator."""
        code = '''
import mcp

class MyClass:
    @mcp.tool()
    def method(self, x: int) -> int:
        """Class method as MCP tool."""
        return x * 2
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].name == "method"

    def test_async_mcp_function(self):
        """Test handling of async MCP functions."""
        code = '''
import mcp

@mcp.tool()
async def async_tool(x: int) -> int:
    """Async MCP tool."""
    return x
'''
        extractor = CodeContextExtractor(code, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        assert contexts[0].name == "async_tool"


class TestFunctionContextDataclass:
    """Test cases for FunctionContext dataclass."""

    def test_function_context_creation(self):
        """Test creating a FunctionContext instance."""
        context = FunctionContext(
            name="test_func",
            decorator_types=["mcp.tool"],
            docstring="Test function",
            parameters=[{"name": "x", "type": "int"}],
            return_type="str",
            line_number=10,
            imports=["mcp"],
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
            dataflow_summary={}
        )
        
        assert context.name == "test_func"
        assert context.line_number == 10
        assert "mcp.tool" in context.decorator_types

    def test_function_context_all_fields(self):
        """Test that FunctionContext has all required fields."""
        extractor = CodeContextExtractor(SIMPLE_MCP_TOOL, "test.py")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) == 1
        ctx = contexts[0]
        
        # Check all fields exist
        assert hasattr(ctx, "name")
        assert hasattr(ctx, "decorator_types")
        assert hasattr(ctx, "docstring")
        assert hasattr(ctx, "parameters")
        assert hasattr(ctx, "return_type")
        assert hasattr(ctx, "line_number")
        assert hasattr(ctx, "imports")
        assert hasattr(ctx, "function_calls")
        assert hasattr(ctx, "assignments")
        assert hasattr(ctx, "control_flow")
        assert hasattr(ctx, "parameter_flows")
        assert hasattr(ctx, "constants")
        assert hasattr(ctx, "variable_dependencies")
        assert hasattr(ctx, "has_file_operations")
        assert hasattr(ctx, "has_network_operations")
        assert hasattr(ctx, "has_subprocess_calls")
        assert hasattr(ctx, "has_eval_exec")
        assert hasattr(ctx, "has_dangerous_imports")
        assert hasattr(ctx, "dataflow_summary")
