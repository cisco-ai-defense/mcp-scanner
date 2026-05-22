# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Cross-language tests for ``NativeAnalyzer.extract_mcp_capability_contexts``.

These tests pin the behavior the behavioral analyzer relies on: only
functions actually exposed as MCP capabilities — tools, prompts, or
resources — should surface, regardless of how many plain helper functions
are defined alongside them.

The capability fixtures below were modeled directly on the canonical
quickstart for each official MCP SDK (TS SDK v1/v2, Python FastMCP, Go SDK,
Spring AI for Java, Kotlin SDK, .NET SDK, rmcp for Rust, php-mcp/server,
and the comment-style annotation pattern used by community Ruby SDKs).
Whenever the SDK examples evolve, update the fixtures in lockstep.
"""

import pytest

from mcpscanner.core.static_analysis import NativeAnalyzer


# ---------------------------------------------------------------------------
# Helper-only fixtures: a file with NO MCP capabilities should yield zero
# capability contexts even when it defines several plain functions.
# ---------------------------------------------------------------------------

HELPERS_ONLY_PYTHON = '''
def _internal_normalize(s: str) -> str:
    return s.strip().lower()

def _validate_number(name, v):
    if not isinstance(v, (int, float)):
        raise TypeError(name)

def util_format(label, value):
    return f"{label}={value}"
'''

HELPERS_ONLY_JAVASCRIPT = """\
function _validate(v) { return v; }
function _coerce(v) { return Number(v); }
function format(label, value) { return label + '=' + value; }
"""

HELPERS_ONLY_TYPESCRIPT = """\
function _validate(v: number): number { return v; }
function _coerce(v: unknown): number { return Number(v); }
export function format(label: string, value: unknown): string { return `${label}=${value}`; }
"""

HELPERS_ONLY_GO = """\
package main

func validate(x float64) error { return nil }

func helper(a, b float64) float64 { return a + b }

func main() {}
"""

HELPERS_ONLY_JAVA = """\
package demo;

public class Helpers {
    public double normalize(double x) { return x; }
    public double helper(double a, double b) { return a + b; }
}
"""

HELPERS_ONLY_KOTLIN = """\
package demo

fun helper(x: Double): Double = x

fun util(a: Double, b: Double): Double = a + b
"""

HELPERS_ONLY_CSHARP = """\
public static class Helpers {
    public static double Normalize(double x) => x;
    public static double Helper(double a, double b) => a + b;
}
"""

HELPERS_ONLY_RUST = """\
fn helper(x: f64) -> f64 { x }

fn util(a: f64, b: f64) -> f64 { a + b }
"""

HELPERS_ONLY_PHP = """\
<?php
class Helpers {
    public function normalize(float $x): float { return $x; }
    public function helper(float $a, float $b): float { return $a + $b; }
}
"""

HELPERS_ONLY_RUBY = """\
def helper(x)
  x
end

def util(a, b)
  a + b
end
"""


HELPERS_ONLY_FIXTURES = [
    pytest.param(HELPERS_ONLY_PYTHON, "helpers.py", id="python"),
    pytest.param(HELPERS_ONLY_JAVASCRIPT, "helpers.js", id="javascript"),
    pytest.param(HELPERS_ONLY_TYPESCRIPT, "helpers.ts", id="typescript"),
    pytest.param(HELPERS_ONLY_GO, "helpers.go", id="go"),
    pytest.param(HELPERS_ONLY_JAVA, "Helpers.java", id="java"),
    pytest.param(HELPERS_ONLY_KOTLIN, "helpers.kt", id="kotlin"),
    pytest.param(HELPERS_ONLY_CSHARP, "Helpers.cs", id="csharp"),
    pytest.param(HELPERS_ONLY_RUST, "helpers.rs", id="rust"),
    pytest.param(HELPERS_ONLY_PHP, "helpers.php", id="php"),
    pytest.param(HELPERS_ONLY_RUBY, "helpers.rb", id="ruby"),
]


@pytest.mark.parametrize("source,path", HELPERS_ONLY_FIXTURES)
def test_helpers_only_files_produce_no_capabilities(source: str, path: str) -> None:
    """A file with zero MCP-decorated/registered functions yields []."""
    analyzer = NativeAnalyzer(source, path)
    capabilities = analyzer.extract_mcp_capability_contexts()
    assert capabilities == [], (
        f"helpers-only fixture for {path!r} unexpectedly returned "
        f"{[c.name for c in capabilities]!r}"
    )


# ---------------------------------------------------------------------------
# Mixed fixtures: 1 MCP capability + N plain helpers in the same file.
# Only the registered/annotated capability must surface.
# ---------------------------------------------------------------------------

MIXED_PYTHON = '''
from fastmcp import FastMCP

mcp = FastMCP("plus-helpers")

def _validate(name, v):
    pass

def _coerce(v):
    return float(v)

@mcp.tool()
def add(a: float, b: float) -> float:
    """Return the sum of two numbers."""
    _validate("a", a); _validate("b", b)
    return _coerce(a) + _coerce(b)
'''

MIXED_JAVASCRIPT = """\
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { z } = require('zod');

const server = new McpServer({ name: 'demo', version: '0.1.0' });

function _validate(v) { return v; }
function _coerce(v) { return Number(v); }

server.tool(
  'add',
  { a: z.number(), b: z.number() },
  async ({ a, b }) => ({ content: [{ type: 'text', text: String(a + b) }] }),
);
"""

MIXED_TYPESCRIPT = """\
import { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

const server = new McpServer({ name: 'demo', version: '1.0.0' });

function _validate(v: number): number { return v; }

server.registerTool(
  'add',
  {
    description: 'Add two numbers',
    inputSchema: z.object({ a: z.number(), b: z.number() }),
  },
  async ({ a, b }: { a: number; b: number }) => ({
    content: [{ type: 'text', text: String(a + b) }],
  }),
);
"""

MIXED_GO = """\
package main

import (
    "context"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

type AddInput struct {
    A float64 `json:"a"`
    B float64 `json:"b"`
}

type AddOutput struct {
    Sum float64 `json:"sum"`
}

func validate(x float64) error { return nil }

func add(ctx context.Context, req *mcp.CallToolRequest, in AddInput) (*mcp.CallToolResult, AddOutput, error) {
    return nil, AddOutput{Sum: in.A + in.B}, nil
}

func main() {
    server := mcp.NewServer(&mcp.Implementation{Name: "demo", Version: "v1.0.0"}, nil)
    mcp.AddTool(server, &mcp.Tool{Name: "add", Description: "Add two numbers"}, add)
}
"""

MIXED_JAVA = """\
package demo;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Service;

@Service
public class CalcService {

    private double normalize(double x) { return x; }

    @Tool(description = "Add two numbers")
    public double add(double a, double b) {
        return normalize(a) + normalize(b);
    }
}
"""

MIXED_KOTLIN = """\
package demo

import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent

fun helper(x: Double): Double = x

fun register(server: Server) {
    server.addTool(
        name = "add",
        description = "Add two numbers",
    ) { request ->
        val a = (request.arguments?.get("a") as Number).toDouble()
        val b = (request.arguments?.get("b") as Number).toDouble()
        CallToolResult(content = listOf(TextContent(text = (helper(a) + helper(b)).toString())))
    }
}
"""

MIXED_CSHARP = """\
using ModelContextProtocol.Server;
using System.ComponentModel;

[McpServerToolType]
public static class CalcTools
{
    private static double Normalize(double x) => x;

    [McpServerTool, Description("Add two numbers")]
    public static double Add(double a, double b) => Normalize(a) + Normalize(b);
}
"""

MIXED_RUST = """\
use rmcp::{tool, tool_router};

#[derive(Clone)]
struct Calculator;

fn helper(x: f64) -> f64 { x }

#[tool_router]
impl Calculator {
    #[tool(description = "Add two numbers")]
    fn add(&self, a: f64, b: f64) -> f64 {
        helper(a) + helper(b)
    }
}
"""

MIXED_PHP = """\
<?php

use PhpMcp\\Server\\Attributes\\McpTool;

class Calc {
    private function helper(float $x): float { return $x; }

    #[McpTool(name: "add", description: "Add two numbers")]
    public function add(float $a, float $b): float {
        return $this->helper($a) + $this->helper($b);
    }
}
"""

MIXED_RUBY = """\
require "mcp"

def helper(x)
  x
end

# @tool name: "add", description: "Add two numbers"
def add(a, b)
  helper(a) + helper(b)
end
"""


# ``expected_names`` is the SET of FunctionContext.name values we want to see
# returned — class-qualified for languages that scope methods inside classes
# (Java/C#/PHP/Rust impl), bare for module-level functions (Python/JS/Go
# named handler/Kotlin trailing lambda/Ruby comment annotation).
MIXED_FIXTURES = [
    pytest.param(MIXED_PYTHON, "mixed.py", {"add"}, id="python"),
    pytest.param(MIXED_JAVASCRIPT, "mixed.js", {"add"}, id="javascript"),
    pytest.param(MIXED_TYPESCRIPT, "mixed.ts", {"add"}, id="typescript"),
    pytest.param(MIXED_GO, "mixed.go", {"add"}, id="go"),
    pytest.param(MIXED_JAVA, "Mixed.java", {"CalcService.add"}, id="java"),
    pytest.param(MIXED_KOTLIN, "mixed.kt", {"add"}, id="kotlin"),
    pytest.param(MIXED_CSHARP, "Mixed.cs", {"CalcTools.Add"}, id="csharp"),
    pytest.param(MIXED_RUST, "mixed.rs", {"Calculator.add"}, id="rust"),
    pytest.param(MIXED_PHP, "mixed.php", {"Calc.add"}, id="php"),
    pytest.param(MIXED_RUBY, "mixed.rb", {"add"}, id="ruby"),
]


@pytest.mark.parametrize("source,path,expected_names", MIXED_FIXTURES)
def test_mixed_files_return_only_capabilities(
    source: str, path: str, expected_names: set
) -> None:
    """One MCP-registered/annotated function alongside helpers must yield
    exactly the registered capability — no helper leakage."""
    analyzer = NativeAnalyzer(source, path)
    capabilities = analyzer.extract_mcp_capability_contexts()
    actual = {c.name for c in capabilities}
    assert actual == expected_names, (
        f"{path!r}: got {actual!r} but expected {expected_names!r}"
    )

    # Sanity: the source file does define more than one function. If we
    # ever return *all* of them we'd be regressing the original bug — the
    # purpose of this test is to assert we filter the rest out.
    full = analyzer.analyze()
    assert full.success
    assert len(full.functions) > len(capabilities), (
        f"{path!r}: extract_mcp_capability_contexts() returned the same "
        f"number of contexts as extract_all_function_contexts(); the test "
        f"fixture must contain at least one non-capability helper to "
        f"meaningfully validate filtering."
    )


# ---------------------------------------------------------------------------
# Capability tagging: ensure each returned context carries metadata so
# downstream code can distinguish how it was discovered.
# ---------------------------------------------------------------------------


def test_python_capability_keeps_decorator_metadata() -> None:
    """Python capabilities retain their original decorator string so callers
    can tell which kind of MCP primitive they correspond to."""
    analyzer = NativeAnalyzer(MIXED_PYTHON, "mixed.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert any(
        d.endswith("tool") or d.endswith("tool()")
        for d in caps[0].decorator_types
    ), caps[0].decorator_types


@pytest.mark.parametrize(
    "source,path,expected_tag",
    [
        (MIXED_JAVASCRIPT, "mixed.js", "<registration>.tool"),
        (MIXED_TYPESCRIPT, "mixed.ts", "<registration>.tool"),
        (MIXED_GO, "mixed.go", "<registration>.tool"),
        (MIXED_KOTLIN, "mixed.kt", "<registration>.tool"),
        (MIXED_JAVA, "Mixed.java", "<annotation>.tool"),
        (MIXED_CSHARP, "Mixed.cs", "<annotation>.tool"),
        (MIXED_RUST, "mixed.rs", "<annotation>.tool"),
        (MIXED_PHP, "mixed.php", "<annotation>.tool"),
        (MIXED_RUBY, "mixed.rb", "<annotation>.tool"),
    ],
)
def test_native_capability_carries_source_kind_tag(
    source: str, path: str, expected_tag: str
) -> None:
    """The synthetic ``<annotation>.tool`` / ``<registration>.tool`` decorator
    tag tells downstream code whether the capability was discovered via a
    function-attached annotation (Java/C#/Rust/PHP/Ruby) or a call-site
    registration (JS/TS/Go/Kotlin)."""
    analyzer = NativeAnalyzer(source, path)
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    assert expected_tag in caps[0].decorator_types, caps[0].decorator_types


# ---------------------------------------------------------------------------
# Backward-compatibility guards
# ---------------------------------------------------------------------------


def test_extract_all_function_contexts_unchanged_for_python() -> None:
    """Sanity check: ``extract_all_function_contexts`` (the legacy method)
    must keep returning *every* function in a file, regardless of MCP
    decoration. Capability filtering is opt-in via the new method."""
    analyzer = NativeAnalyzer(MIXED_PYTHON, "mixed.py")
    full = analyzer.extract_all_function_contexts()
    names = {fn.name for fn in full}
    assert {"_validate", "_coerce", "add"}.issubset(names), names


def test_unsupported_language_returns_empty() -> None:
    """Languages without a tree-sitter parser should produce ``[]`` rather
    than raising."""
    analyzer = NativeAnalyzer("// Some Swift code\nfunc foo() {}\n", "demo.swift")
    # Swift isn't in FUNCTION_NODE_TYPES, so capability extraction must
    # short-circuit to an empty list. (If Swift support is added later,
    # this test should be expanded with a real fixture rather than
    # deleted.)
    if analyzer.language not in analyzer.FUNCTION_NODE_TYPES:
        assert analyzer.extract_mcp_capability_contexts() == []
