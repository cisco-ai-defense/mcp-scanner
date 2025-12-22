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

"""Tests for forward dataflow analysis with Python, TypeScript, and Kotlin."""

from pathlib import Path

import pytest

from mcpscanner.core.static_analysis.parser.python_parser import PythonParser
from mcpscanner.core.static_analysis.parser.typescript_parser import TypeScriptParser
from mcpscanner.core.static_analysis.parser.kotlin_parser import KotlinParser
from mcpscanner.core.static_analysis.dataflow.forward_analysis import ForwardDataflowAnalysis


class TestForwardAnalysisPython:
    """Test forward dataflow analysis for Python."""

    def test_simple_parameter_flow(self):
        """Test tracking parameter flow through assignment."""
        source = """
def process(user_input):
    data = user_input
    result = data.strip()
    return result
"""
        parser = PythonParser(Path("test.py"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["user_input"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        assert flow.parameter_name == "user_input"
        # Parameter flows to assignment
        assert len(flow.reaches_assignments) > 0
        assert "data = user_input" in flow.reaches_assignments

    def test_parameter_reaches_function_call(self):
        """Test tracking parameter to function call."""
        source = """
def process(filename):
    f = open(filename)
    content = f.read()
    return content
"""
        parser = PythonParser(Path("test.py"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["filename"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        # Parameter flows to open() call via assignment
        assert "open" in flow.reaches_calls
        # And transitively to read() via f
        assert flow.reaches_returns

    def test_multiple_parameters(self):
        """Test tracking multiple parameters."""
        source = """
def process(name, value):
    result = f"{name}: {value}"
    print(result)
    return result
"""
        parser = PythonParser(Path("test.py"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["name", "value"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 2
        param_names = {f.parameter_name for f in flows}
        assert "name" in param_names
        assert "value" in param_names


class TestForwardAnalysisTypeScript:
    """Test forward dataflow analysis for TypeScript."""

    def test_simple_parameter_flow_ts(self):
        """Test tracking parameter flow in TypeScript."""
        source = """
function process(userInput: string): string {
    const data = userInput;
    const result = data.trim();
    return result;
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["userInput"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        assert flow.parameter_name == "userInput"

    def test_parameter_reaches_call_ts(self):
        """Test tracking parameter to function call in TypeScript."""
        source = """
async function fetchData(url: string): Promise<any> {
    const response = await fetch(url);
    const data = await response.json();
    return data;
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["url"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        assert "fetch" in flow.reaches_calls

    def test_arrow_function_ts(self):
        """Test tracking in arrow functions."""
        source = """
const processData = (input: string) => {
    const processed = input.toLowerCase();
    console.log(processed);
    return processed;
};
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["input"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        assert flow.parameter_name == "input"

    def test_template_string_ts(self):
        """Test tracking through template strings."""
        source = """
function greet(name: string): string {
    const message = `Hello, ${name}!`;
    return message;
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["name"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        assert flow.parameter_name == "name"


class TestForwardAnalysisKotlin:
    """Test forward dataflow analysis for Kotlin."""

    def test_simple_parameter_flow_kt(self):
        """Test tracking parameter flow in Kotlin."""
        source = """
fun process(userInput: String): String {
    val data = userInput
    val result = data.trim()
    return result
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["userInput"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        assert flow.parameter_name == "userInput"

    def test_parameter_reaches_call_kt(self):
        """Test tracking parameter to function call in Kotlin."""
        source = """
fun readFile(filename: String): String {
    val content = File(filename).readText()
    return content
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["filename"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        # File is called with filename
        assert len(flow.reaches_calls) > 0

    def test_lambda_parameter_kt(self):
        """Test tracking in lambda expressions."""
        source = """
fun processItems(items: List<String>): List<String> {
    return items.map { it.uppercase() }
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["items"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        assert flow.parameter_name == "items"

    def test_string_template_kt(self):
        """Test tracking through string templates."""
        source = """
fun greet(name: String): String {
    val message = "Hello, $name!"
    return message
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["name"])
        flows = analysis.analyze_forward_flows()
        
        assert len(flows) == 1
        flow = flows[0]
        assert flow.parameter_name == "name"


class TestCFGBuilding:
    """Test CFG building for different languages."""

    def test_python_cfg(self):
        """Test CFG building for Python."""
        source = """
def test(x):
    if x > 0:
        return x
    else:
        return -x
"""
        parser = PythonParser(Path("test.py"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["x"])
        analysis.build_cfg()
        
        assert analysis.cfg is not None
        assert analysis.cfg.entry is not None
        assert analysis.cfg.exit is not None
        assert len(analysis.cfg.nodes) > 0

    def test_typescript_cfg(self):
        """Test CFG building for TypeScript."""
        source = """
function test(x: number): number {
    if (x > 0) {
        return x;
    } else {
        return -x;
    }
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["x"])
        analysis.build_cfg()
        
        assert analysis.cfg is not None
        assert analysis.cfg.entry is not None
        assert len(analysis.cfg.nodes) > 0

    def test_kotlin_cfg(self):
        """Test CFG building for Kotlin."""
        source = """
fun test(x: Int): Int {
    return if (x > 0) {
        x
    } else {
        -x
    }
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["x"])
        analysis.build_cfg()
        
        assert analysis.cfg is not None
        assert analysis.cfg.entry is not None
        assert len(analysis.cfg.nodes) > 0

    def test_loop_cfg_python(self):
        """Test CFG with loops in Python."""
        source = """
def process(items):
    result = []
    for item in items:
        result.append(item)
    return result
"""
        parser = PythonParser(Path("test.py"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["items"])
        analysis.build_cfg()
        
        assert analysis.cfg is not None
        # Should have loop back edge
        assert len(analysis.cfg.nodes) > 3

    def test_try_catch_cfg_typescript(self):
        """Test CFG with try-catch in TypeScript."""
        source = """
function process(data: string): string {
    try {
        return JSON.parse(data);
    } catch (e) {
        return "error";
    }
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["data"])
        analysis.build_cfg()
        
        assert analysis.cfg is not None
        assert len(analysis.cfg.nodes) > 3

    def test_when_cfg_kotlin(self):
        """Test CFG with when expression in Kotlin."""
        source = """
fun describe(x: Int): String {
    return when (x) {
        1 -> "one"
        2 -> "two"
        else -> "other"
    }
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        analysis = ForwardDataflowAnalysis(parser, ["x"])
        analysis.build_cfg()
        
        assert analysis.cfg is not None
        assert len(analysis.cfg.nodes) > 3
