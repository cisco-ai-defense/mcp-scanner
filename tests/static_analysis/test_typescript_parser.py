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

"""Tests for TypeScript parser."""

from pathlib import Path

import pytest

from mcpscanner.core.static_analysis.parser.typescript_parser import TypeScriptParser


class TestTypeScriptParser:
    """Test TypeScript parser functionality."""

    def test_parse_simple_function(self):
        """Test parsing a simple function declaration."""
        source = """
function greet(name: string): string {
    return `Hello, ${name}!`;
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        tree = parser.parse()
        
        assert tree is not None
        assert not tree.root_node.has_error

    def test_parse_arrow_function(self):
        """Test parsing arrow functions."""
        source = """
const add = (a: number, b: number): number => a + b;

const multiply = (a: number, b: number): number => {
    return a * b;
};
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        tree = parser.parse()
        
        assert tree is not None
        funcs = parser.get_function_defs()
        assert len(funcs) >= 2

    def test_parse_class_with_methods(self):
        """Test parsing a class with methods."""
        source = """
class Calculator {
    private value: number = 0;
    
    add(n: number): Calculator {
        this.value += n;
        return this;
    }
    
    getValue(): number {
        return this.value;
    }
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        tree = parser.parse()
        
        assert tree is not None
        classes = parser.get_class_defs()
        assert len(classes) == 1

    def test_get_function_calls(self):
        """Test extracting function calls."""
        source = """
function main() {
    console.log("Hello");
    fetch("https://api.example.com/data");
    process.exit(0);
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        calls = parser.get_function_calls()
        call_names = [parser.get_call_name(c) for c in calls]
        
        assert "console.log" in call_names
        assert "fetch" in call_names
        assert "process.exit" in call_names

    def test_get_imports(self):
        """Test extracting import statements."""
        source = """
import { readFile } from 'fs';
import * as path from 'path';
import express from 'express';
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        imports = parser.get_imports()
        assert len(imports) == 3

    def test_get_assignments(self):
        """Test extracting assignments."""
        source = """
const x = 10;
let y = "hello";
var z = true;
x = 20;
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        assignments = parser.get_assignments()
        assert len(assignments) >= 3

    def test_get_function_parameters(self):
        """Test extracting function parameters."""
        source = """
function processData(
    input: string,
    options?: { verbose: boolean },
    ...rest: number[]
): void {
    console.log(input);
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        funcs = parser.get_function_defs()
        assert len(funcs) == 1
        
        params = parser.get_function_parameters(funcs[0])
        assert len(params) >= 1
        assert params[0].get('name') == 'input'

    def test_get_string_literals(self):
        """Test extracting string literals."""
        source = """
const url = "https://api.example.com";
const message = 'Hello World';
const template = `Value is ${x}`;
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        strings = parser.get_string_literals()
        assert "https://api.example.com" in strings
        assert "Hello World" in strings

    def test_get_node_range(self):
        """Test getting node source range."""
        source = """function test() {
    return 42;
}"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        funcs = parser.get_function_defs()
        assert len(funcs) == 1
        
        range_obj = parser.get_node_range(funcs[0])
        assert range_obj.start.line == 1
        assert range_obj.end.line == 3

    def test_parse_mcp_server_code(self):
        """Test parsing MCP server TypeScript code."""
        source = """
import { McpServer } from '@modelcontextprotocol/server';

const server = new McpServer({
    name: 'test-server',
    version: '1.0.0'
});

server.registerTool(
    'greet',
    {
        description: 'Greet a user',
        inputSchema: {
            name: z.string()
        }
    },
    async ({ name }) => {
        return {
            content: [{ type: 'text', text: `Hello, ${name}!` }]
        };
    }
);
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        tree = parser.parse()
        
        assert tree is not None
        calls = parser.get_function_calls()
        call_names = [parser.get_call_name(c) for c in calls]
        
        assert "server.registerTool" in call_names

    def test_parse_tsx_file(self):
        """Test parsing TSX (React TypeScript) file."""
        source = """
import React from 'react';

interface Props {
    name: string;
}

const Greeting: React.FC<Props> = ({ name }) => {
    return <div>Hello, {name}!</div>;
};

export default Greeting;
"""
        parser = TypeScriptParser(Path("test.tsx"), source, is_tsx=True)
        tree = parser.parse()
        
        assert tree is not None

    def test_is_call_to(self):
        """Test checking if node is a call to specific function."""
        source = """
fetch("https://api.example.com");
console.log("test");
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        calls = parser.get_function_calls()
        
        fetch_calls = [c for c in calls if parser.is_call_to(c, "fetch")]
        assert len(fetch_calls) == 1
        
        log_calls = [c for c in calls if parser.is_call_to(c, "log")]
        assert len(log_calls) == 1

    def test_walk_ast(self):
        """Test walking the AST."""
        source = """
function outer() {
    function inner() {
        return 1;
    }
    return inner();
}
"""
        parser = TypeScriptParser(Path("test.ts"), source)
        parser.parse()
        
        all_nodes = parser.walk()
        assert len(all_nodes) > 0
        
        # Should find multiple function declarations
        func_nodes = [n for n in all_nodes if n.type in {'function_declaration', 'function_expression'}]
        assert len(func_nodes) >= 1
