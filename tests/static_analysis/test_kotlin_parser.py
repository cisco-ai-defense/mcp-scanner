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

"""Tests for Kotlin parser."""

from pathlib import Path

import pytest

from mcpscanner.core.static_analysis.parser.kotlin_parser import KotlinParser


class TestKotlinParser:
    """Test Kotlin parser functionality."""

    def test_parse_simple_function(self):
        """Test parsing a simple function declaration."""
        source = """
fun greet(name: String): String {
    return "Hello, $name!"
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        tree = parser.parse()
        
        assert tree is not None
        assert not tree.root_node.has_error

    def test_parse_class_with_methods(self):
        """Test parsing a class with methods."""
        source = """
class Calculator {
    private var value: Int = 0
    
    fun add(n: Int): Calculator {
        value += n
        return this
    }
    
    fun getValue(): Int {
        return value
    }
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        tree = parser.parse()
        
        assert tree is not None
        classes = parser.get_class_defs()
        assert len(classes) == 1

    def test_get_function_calls(self):
        """Test extracting function calls."""
        source = """
fun main() {
    println("Hello")
    listOf(1, 2, 3).forEach { println(it) }
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        calls = parser.get_function_calls()
        call_names = [parser.get_call_name(c) for c in calls]
        
        assert "println" in call_names

    def test_get_imports(self):
        """Test extracting import statements."""
        source = """
import io.ktor.server.application.Application
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        imports = parser.get_imports()
        assert len(imports) == 3

    def test_get_assignments(self):
        """Test extracting assignments."""
        source = """
fun test() {
    val x = 10
    var y = "hello"
    val z = true
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        assignments = parser.get_assignments()
        assert len(assignments) >= 3

    def test_get_function_parameters(self):
        """Test extracting function parameters."""
        source = """
fun processData(
    input: String,
    options: Map<String, Any>?,
    vararg rest: Int
): Unit {
    println(input)
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        funcs = parser.get_function_defs()
        assert len(funcs) == 1
        
        params = parser.get_function_parameters(funcs[0])
        assert len(params) >= 1

    def test_get_string_literals(self):
        """Test extracting string literals."""
        source = """
fun test() {
    val url = "https://api.example.com"
    val message = "Hello World"
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        strings = parser.get_string_literals()
        assert "https://api.example.com" in strings
        assert "Hello World" in strings

    def test_get_node_range(self):
        """Test getting node source range."""
        source = """fun test() {
    return 42
}"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        funcs = parser.get_function_defs()
        assert len(funcs) == 1
        
        range_obj = parser.get_node_range(funcs[0])
        assert range_obj.start.line == 1

    def test_parse_mcp_server_code(self):
        """Test parsing MCP server Kotlin code."""
        source = """
import io.modelcontextprotocol.kotlin.sdk.server.Server

fun configureServer(): Server {
    val server = Server(
        Implementation(name = "test-server", version = "1.0.0"),
        ServerOptions()
    )

    server.addTool(
        name = "kotlin-tool",
        description = "A test tool"
    ) { _ ->
        CallToolResult(content = listOf(TextContent("Hello!")))
    }

    return server
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        tree = parser.parse()
        
        assert tree is not None
        calls = parser.get_function_calls()
        call_names = [parser.get_call_name(c) for c in calls]
        
        assert "server.addTool" in call_names

    def test_is_call_to(self):
        """Test checking if node is a call to specific function."""
        source = """
fun test() {
    println("test")
    listOf(1, 2, 3)
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        calls = parser.get_function_calls()
        
        println_calls = [c for c in calls if parser.is_call_to(c, "println")]
        assert len(println_calls) == 1

    def test_walk_ast(self):
        """Test walking the AST."""
        source = """
fun outer() {
    fun inner() {
        return 1
    }
    return inner()
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        parser.parse()
        
        all_nodes = parser.walk()
        assert len(all_nodes) > 0
        
        # Should find function declarations
        func_nodes = [n for n in all_nodes if n.type == 'function_declaration']
        assert len(func_nodes) >= 1

    def test_lambda_literal(self):
        """Test parsing lambda literals."""
        source = """
fun test() {
    val action = { x: Int -> x * 2 }
    listOf(1, 2, 3).map { it * 2 }
}
"""
        parser = KotlinParser(Path("test.kt"), source)
        tree = parser.parse()
        
        assert tree is not None
        funcs = parser.get_function_defs()
        # Should find the main function and lambda literals
        assert len(funcs) >= 1

    def test_when_expression(self):
        """Test parsing when expressions."""
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
        tree = parser.parse()
        
        assert tree is not None
        assert not tree.root_node.has_error
