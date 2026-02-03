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

"""Tests for NativeAnalyzer - fallback AST-based analyzer."""

import pytest


class TestNativeAnalyzerPython:
    """Test native analyzer for Python code."""

    def test_import_native_analyzer(self):
        """Test that NativeAnalyzer can be imported."""
        from mcpscanner.core.static_analysis import NativeAnalyzer, NativeAnalysisResult

        assert NativeAnalyzer is not None
        assert NativeAnalysisResult is not None

    def test_analyze_simple_function(self):
        """Test analyzing a simple Python function."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def greet(name: str) -> str:
    """Greet a person by name."""
    return f"Hello, {name}!"
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        assert result.language == "python"
        assert len(result.functions) == 1

        func = result.functions[0]
        assert func.name == "greet"
        assert func.docstring == "Greet a person by name."
        assert len(func.parameters) == 1
        assert func.parameters[0]["name"] == "name"
        assert func.parameters[0]["type"] == "str"
        assert func.return_type == "str"

    def test_analyze_function_with_calls(self):
        """Test that function calls are extracted from AST."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def process_file(path: str):
    """Process a file."""
    with open(path, 'r') as f:
        data = f.read()
    result = json.loads(data)
    return result
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]

        # Check that calls are extracted (not pattern-matched)
        call_names = [c["name"] for c in func.function_calls]
        assert "open" in call_names
        assert "f.read" in call_names
        assert "json.loads" in call_names

    def test_analyze_function_with_decorators(self):
        """Test that decorators are extracted from AST."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
@app.route("/api/data")
@require_auth
def get_data():
    """Get data from API."""
    return {"data": "value"}
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]
        assert "app.route" in func.decorator_types
        assert "require_auth" in func.decorator_types

    def test_analyze_mcp_decorated_function(self):
        """Test that MCP-decorated functions work without special handling."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
import mcp

@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from disk."""
    with open(path, 'r') as f:
        return f.read()
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]
        assert func.name == "read_file"
        assert "mcp.tool" in func.decorator_types

    def test_analyze_control_flow(self):
        """Test that control flow is extracted from AST."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def complex_function(x: int) -> int:
    """A function with control flow."""
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                continue
        return x
    else:
        while x < 0:
            x += 1
        return 0
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]

        # Check control flow extracted from AST
        assert len(func.control_flow["if_statements"]) >= 2
        assert len(func.control_flow["for_loops"]) >= 1
        assert len(func.control_flow["while_loops"]) >= 1

    def test_analyze_assignments(self):
        """Test that assignments are extracted from AST."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def process():
    x = 10
    y: int = 20
    z = x + y
    return z
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]

        # Check assignments extracted from AST
        targets = [a["target"] for a in func.assignments]
        assert "x" in targets
        assert "y" in targets
        assert "z" in targets

    def test_analyze_string_literals(self):
        """Test that string literals are extracted from AST."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def make_request():
    url = "https://api.example.com/data"
    headers = {"Authorization": "Bearer token123"}
    return url, headers
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]

        # Check strings extracted from AST
        assert "https://api.example.com/data" in func.string_literals
        assert "Authorization" in func.string_literals
        assert "Bearer token123" in func.string_literals

    def test_analyze_exception_handlers(self):
        """Test that exception handlers are extracted from AST."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def safe_divide(a, b):
    try:
        return a / b
    except ZeroDivisionError as e:
        return None
    except Exception:
        raise
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]

        # Check exception handlers extracted from AST
        assert len(func.exception_handlers) == 2
        types = [h["type"] for h in func.exception_handlers]
        assert "ZeroDivisionError" in types
        assert "Exception" in types

    def test_no_hardcoded_patterns(self):
        """Test that security flags are NOT set by hardcoded patterns."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def dangerous_function():
    import subprocess
    subprocess.run(["ls", "-la"])
    eval("1+1")
    with open("/etc/passwd") as f:
        return f.read()
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]

        # These should all be False - LLM determines security relevance
        assert func.has_file_operations is False
        assert func.has_network_operations is False
        assert func.has_subprocess_calls is False
        assert func.has_eval_exec is False

        # But the calls ARE extracted for LLM to analyze
        call_names = [c["name"] for c in func.function_calls]
        assert "subprocess.run" in call_names
        assert "eval" in call_names
        assert "open" in call_names

    def test_language_detection(self):
        """Test language detection from file extension."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        py_analyzer = NativeAnalyzer("def foo(): pass", "test.py")
        assert py_analyzer.language == "python"

        ts_analyzer = NativeAnalyzer("function foo() {}", "test.ts")
        assert ts_analyzer.language == "typescript"

        js_analyzer = NativeAnalyzer("function foo() {}", "test.js")
        assert js_analyzer.language == "javascript"

    def test_syntax_error_handling(self):
        """Test that syntax errors are handled gracefully."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def broken function(
    this is not valid python
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is False
        assert len(result.errors) > 0
        assert "Syntax error" in result.errors[0]


class TestNativeAnalyzerJavaScript:
    """Test native analyzer for JavaScript/TypeScript code."""

    def test_js_analysis_requires_tree_sitter(self):
        """Test that JS analysis reports if tree-sitter is missing."""
        from mcpscanner.core.static_analysis import NativeAnalyzer
        from mcpscanner.core.static_analysis.native_analyzer import TREE_SITTER_AVAILABLE

        code = '''
function greet(name) {
    return "Hello, " + name;
}
'''
        analyzer = NativeAnalyzer(code, "test.js")
        result = analyzer.analyze()

        if TREE_SITTER_AVAILABLE:
            assert result.success is True
            assert len(result.functions) >= 1
        else:
            assert result.success is False
            assert "tree-sitter" in result.errors[0].lower()

    @pytest.mark.skipif(
        not pytest.importorskip("tree_sitter", reason="tree-sitter not installed"),
        reason="tree-sitter not installed"
    )
    def test_js_function_extraction(self):
        """Test extracting JavaScript functions via tree-sitter AST."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
function fetchData(url) {
    return fetch(url).then(r => r.json());
}

const processData = async (data) => {
    const result = await transform(data);
    return result;
};
'''
        analyzer = NativeAnalyzer(code, "test.js")
        result = analyzer.analyze()

        if result.success:
            assert len(result.functions) >= 2
            names = [f.name for f in result.functions]
            assert "fetchData" in names
            assert "processData" in names


class TestNativeAnalyzerIntegration:
    """Integration tests for NativeAnalyzer."""

    def test_output_matches_function_context(self):
        """Test that output matches FunctionContext dataclass."""
        from mcpscanner.core.static_analysis import NativeAnalyzer, FunctionContext
        from dataclasses import fields

        code = '''
def example():
    """Example function."""
    return 42
'''
        analyzer = NativeAnalyzer(code, "test.py")
        result = analyzer.analyze()

        assert result.success is True
        func = result.functions[0]

        # Verify it's a proper FunctionContext
        assert isinstance(func, FunctionContext)

        # Verify all required fields are present
        required_fields = {f.name for f in fields(FunctionContext) if f.default is f.default_factory}
        for field_name in ["name", "decorator_types", "imports", "function_calls"]:
            assert hasattr(func, field_name)

    def test_extract_all_function_contexts(self):
        """Test the main entry point method."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        code = '''
def func1():
    pass

def func2():
    pass

class MyClass:
    def method1(self):
        pass
'''
        analyzer = NativeAnalyzer(code, "test.py")
        contexts = analyzer.extract_all_function_contexts()

        assert len(contexts) >= 3
        names = [c.name for c in contexts]
        assert "func1" in names
        assert "func2" in names
        assert "method1" in names
