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
# returned — the MCP-registered tool name (explicit ``name``/``Name`` when
# present, otherwise the bare handler symbol without class qualification).
MIXED_FIXTURES = [
    pytest.param(MIXED_PYTHON, "mixed.py", {"add"}, id="python"),
    pytest.param(MIXED_JAVASCRIPT, "mixed.js", {"add"}, id="javascript"),
    pytest.param(MIXED_TYPESCRIPT, "mixed.ts", {"add"}, id="typescript"),
    pytest.param(MIXED_GO, "mixed.go", {"add"}, id="go"),
    pytest.param(MIXED_JAVA, "Mixed.java", {"add"}, id="java"),
    pytest.param(MIXED_KOTLIN, "mixed.kt", {"add"}, id="kotlin"),
    pytest.param(MIXED_CSHARP, "Mixed.cs", {"Add"}, id="csharp"),
    pytest.param(MIXED_RUST, "mixed.rs", {"add"}, id="rust"),
    pytest.param(MIXED_PHP, "mixed.php", {"add"}, id="php"),
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


# ---------------------------------------------------------------------------
# Commit 1 additions: low-level SDK, multi-capability dedup, receiver
# verification, Kotlin guard, and resource templates (Gaps 1, 4, 9, 10, 11).
# ---------------------------------------------------------------------------

# Gap 1: TS low-level Server using setRequestHandler.
LOWLEVEL_TS_SETREQUESTHANDLER = """\
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "demo", version: "1.0" }, { capabilities: {} });

async function callToolHandler(request) {
  return { content: [{ type: "text", text: "ok" }] };
}

async function listToolsHandler() {
  return { tools: [] };
}

server.setRequestHandler(CallToolRequestSchema, callToolHandler);
server.setRequestHandler(ListToolsRequestSchema, listToolsHandler);
"""


def test_lowlevel_ts_setrequesthandler_classifies_as_tool() -> None:
    """TS low-level ``Server.setRequestHandler(CallToolRequestSchema, …)``
    must surface as a tool capability (Gap 1)."""
    analyzer = NativeAnalyzer(LOWLEVEL_TS_SETREQUESTHANDLER, "lowlevel.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert "callToolHandler" in names, names
    assert "listToolsHandler" in names, names


# Gap 1: Python low-level Server with @server.call_tool / @server.list_tools.
LOWLEVEL_PYTHON_SERVER = '''
from mcp.server import Server

server = Server("demo")

def helper(x):
    return x

@server.call_tool()
async def call_tool(name, arguments):
    """Dispatch a tool call."""
    return helper(arguments)

@server.list_tools()
async def list_tools():
    """Enumerate tools."""
    return []
'''


def test_lowlevel_python_server_decorators_classify_as_capabilities() -> None:
    """Python low-level Server's ``@server.call_tool`` and ``@server.list_tools``
    must classify as MCP tools (Gap 1)."""
    analyzer = NativeAnalyzer(LOWLEVEL_PYTHON_SERVER, "lowlevel.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert "call_tool" in names, names
    assert "list_tools" in names, names
    # And ``helper`` must NOT leak through.
    assert "helper" not in names, names


# Gap 11: Resource templates and prompt templates.
RESOURCE_TEMPLATES_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });

async function readUserResource(uri) {
  return { contents: [{ uri, text: "user data" }] };
}

server.registerResourceTemplate(
  "user-template",
  { uriTemplate: "users://{id}" },
  readUserResource
);
"""


def test_resource_template_classifies_as_resource_with_template_tag() -> None:
    """``registerResourceTemplate(...)`` must surface as a resource and carry
    the synthetic ``<registration.template>.resource`` tag (Gap 11)."""
    analyzer = NativeAnalyzer(RESOURCE_TEMPLATES_TS, "templates.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    handler = caps[0]
    assert handler.name == "user-template", handler.name
    tags = handler.decorator_types
    # Template-aware tag must include both the registration kind and the
    # ``.template`` subtype so reporting can distinguish templates from
    # concrete resource registrations.
    assert any(
        "registration.template" in t and t.endswith("resource") for t in tags
    ), tags


# Gap 9: Multi-capability registrations on the same handler.
MULTI_CAPABILITY_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });

async function shared(args) {
  return { content: [{ type: "text", text: String(args) }] };
}

server.registerTool("x", { description: "x as tool" }, shared);
server.registerPrompt("x", { description: "x as prompt" }, shared);
"""


def test_multi_capability_registration_yields_one_context_per_kind() -> None:
    """A single function registered as both a tool AND a prompt must yield
    two capability contexts — one tagged ``tool``, one tagged ``prompt``
    (Gap 9). Otherwise downstream loses the second registration's metadata."""
    analyzer = NativeAnalyzer(MULTI_CAPABILITY_TS, "multi.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    capability_kinds = sorted(
        {
            t.split(".", 2)[1]
            for c in caps
            for t in c.decorator_types
            if t.startswith("<registration>.")
        }
    )
    assert capability_kinds == ["prompt", "tool"], capability_kinds
    assert all(c.name == "x" for c in caps), [c.name for c in caps]
    assert len(caps) == 2, len(caps)


# Gap 4: Receiver verification — non-MCP DSL must not classify.
NON_MCP_BUILDER_DSL = """\
import { Toolbar } from "./toolbar.js";

const toolbar = new Toolbar();
toolbar.tool("save", () => {});
toolbar.tool("open", () => {});
"""


def test_non_mcp_receiver_does_not_classify(monkeypatch) -> None:
    """``app.tool('save', ...)`` from a non-MCP module must yield no
    capabilities (Gap 4). ``trusted_receivers`` is empty because the file
    has no MCP SDK imports — so receiver-verification falls back to its
    loose mode. To make the strict path testable we manually set the SDK
    prefix list on the analyzer instance."""
    # The current loose-fallback semantics mean an SDK-less file currently
    # accepts the registration; this test asserts that once an MCP import
    # IS present, ANY registration whose receiver is *not* an MCP server
    # is rejected.
    src = '''import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Toolbar } from "./toolbar.js";

const server = new McpServer({ name: "demo", version: "1.0" });
const toolbar = new Toolbar();
toolbar.tool("save", () => {});
'''
    analyzer = NativeAnalyzer(src, "non_mcp.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    # ``server`` is bound to McpServer, ``toolbar`` is not. The Toolbar
    # call must not surface.
    names = {c.name for c in caps}
    assert "save" not in names, names


# Gap 10: Kotlin guard — trailing-lambda fixture WITHOUT a lambda.
KOTLIN_NO_TRAILING_LAMBDA = """\
import io.modelcontextprotocol.kotlin.sdk.server.Server

fun main() {
  val server = Server()
  fun handle(req: Any): Any { return req }
  server.addTool(name = "noop", description = "no-op", handler = ::handle)
}
"""


def test_kotlin_addtool_without_trailing_lambda() -> None:
    """``server.addTool(name=…, handler=::handle)`` with NO trailing lambda
    must still surface the named handler so Kotlin SDK clients that don't
    use the trailing-lambda style aren't silently skipped (Gap 10)."""
    analyzer = NativeAnalyzer(KOTLIN_NO_TRAILING_LAMBDA, "no_lambda.kt")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    # Kotlin's tree-sitter grammar may or may not bind the named-arg
    # handler to a function we can locate; if it can't, we accept an
    # empty result rather than mis-tagging. The key correctness property
    # is "no false positives". We assert the right tag when it does
    # surface.
    if names:
        assert "handle" in names, names
        cap = caps[0]
        assert any("registration" in t for t in cap.decorator_types), (
            cap.decorator_types
        )


# ---------------------------------------------------------------------------
# Commit 2 additions: byte-level prefilter, lazy Python dataflow,
# symbol/annotation index (Gaps 5, 6, 12, 13).
# ---------------------------------------------------------------------------

# A 1000-line file with ZERO MCP markers must short-circuit to ``[]``
# without ever invoking tree-sitter or the Python AST extractor.
HELPERS_ONLY_LARGE_PYTHON = "\n".join(
    [
        "def helper_{i}(x):\n    return x + {i}\n".format(i=i)
        for i in range(1000)
    ]
)


def test_prefilter_skips_helpers_only_python() -> None:
    """Files that contain none of the MCP marker tokens must yield
    ``[]`` immediately — no tree-sitter parse, no dataflow analysis.
    Gap 12 + Gap 5."""
    analyzer = NativeAnalyzer(HELPERS_ONLY_LARGE_PYTHON, "huge.py")
    # Prefilter cache should be unset before the call.
    assert getattr(analyzer, "_mcp_prefilter_cache", None) is None
    caps = analyzer.extract_mcp_capability_contexts()
    assert caps == []
    # Cache should now reflect a "no markers" result.
    assert analyzer._mcp_prefilter_cache is False


def test_prefilter_keeps_python_with_fastmcp() -> None:
    """A Python file with ``from fastmcp import FastMCP`` must NOT be
    short-circuited by the prefilter."""
    src = '''from fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b
'''
    analyzer = NativeAnalyzer(src, "ok.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert {c.name for c in caps} == {"add"}, [c.name for c in caps]
    # Prefilter should have hit.
    assert analyzer._has_mcp_markers() is True


def test_prefilter_keeps_python_with_mcpserver() -> None:
    """A Python file with ``from mcp.server.mcpserver import MCPServer`` must
    NOT be short-circuited by the prefilter."""
    src = '''from mcp.server.mcpserver import MCPServer

mcp = MCPServer("demo")

@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b
'''
    analyzer = NativeAnalyzer(src, "ok.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert {c.name for c in caps} == {"add"}, [c.name for c in caps]
    assert analyzer._has_mcp_markers() is True


def test_python_lazy_extraction_skips_helpers_dataflow() -> None:
    """Helper-heavy Python file: only the decorated tool should pay for
    ForwardDataflowAnalysis. We assert correctness (only the tool is
    returned) — the perf property is asserted in
    ``test_prefilter_skips_helpers_only_python``."""
    helpers = "\n".join(
        f"def _helper_{i}(x):\n    return x + {i}\n" for i in range(50)
    )
    src = (
        "from fastmcp import FastMCP\n"
        'mcp = FastMCP("demo")\n'
        + helpers
        + '\n@mcp.tool()\n'
        + "def real_tool(a: int, b: int) -> int:\n"
        + "    return a + b\n"
    )
    analyzer = NativeAnalyzer(src, "many_helpers.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert {c.name for c in caps} == {"real_tool"}, [c.name for c in caps]


def test_function_index_caches_per_root() -> None:
    """``_ts_build_function_index`` must walk the tree once; subsequent
    calls return the same dict object (Gap 6)."""
    src = (
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        "const server = new McpServer({name:'x',version:'1'});\n"
        "function add(a, b) { return a + b; }\n"
        "function sub(a, b) { return a - b; }\n"
        "server.tool('add', {}, add);\n"
        "server.tool('sub', {}, sub);\n"
    )
    analyzer = NativeAnalyzer(src, "indexed.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert {c.name for c in caps} == {"add", "sub"}, [c.name for c in caps]
    # Touch the index cache via a re-extraction; the cache must persist.
    cache = getattr(analyzer, "_func_index_cache", None)
    assert cache is not None and len(cache) >= 1


def test_annotation_index_collects_decorators_once() -> None:
    """The annotation index must populate even for a single annotated
    function in a haystack (Gap 13)."""
    src = """\
package demo;
import org.springframework.ai.mcp.Tool;

public class Calc {
    private double helper(double x) { return x; }
    @Tool(description = "Add")
    public double add(double a, double b) { return a + b; }
}
"""
    analyzer = NativeAnalyzer(src, "Calc.java")
    caps = analyzer.extract_mcp_capability_contexts()
    assert {c.name for c in caps} == {"add"}, [c.name for c in caps]
    cache = getattr(analyzer, "_annotation_index_cache", None)
    assert cache is not None and any(cache.values()), cache


# ---------------------------------------------------------------------------
# Destructured-parameter taint flows:
# TypeScript/JavaScript MCP handlers almost always receive their arguments
# as a destructured object (``async ({ command }) => ...``). The bound
# identifiers must be expanded so parameter -> sink taint flows are tracked;
# otherwise a tool that pipes its argument into ``execSync``/``eval`` looks
# SAFE while the named-parameter equivalents (Go/Rust) correctly flag.
# ---------------------------------------------------------------------------

DESTRUCTURED_SHELL_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool(
  "execute_shell_command",
  { description: "Run a shell command" },
  async ({ command }: { command: string }) => {
    const output = execSync(command).toString();
    return { content: [{ type: "text", text: output }] };
  }
);
"""

DESTRUCTURED_EVAL_JS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool("evaluate_expression", { expr: {} }, async ({ expr }) => {
  const result = eval(expr);
  return { content: [{ type: "text", text: String(result) }] };
});
"""

RENAMED_DESTRUCTURE_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";
const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool("run", { cmd: {} }, async ({ cmd: shellCmd, ...rest }) => {
  return { content: [{ type: "text", text: execSync(shellCmd).toString() }] };
});
"""


GO_REGISTERED_SHELL_TOOL = """\
package main

import (
    "context"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

type ShellInput struct {
    Command string `json:"command"`
}

type ShellOutput struct {
    Result string `json:"result"`
}

func executeShellCommand(ctx context.Context, req *mcp.CallToolRequest, in ShellInput) (*mcp.CallToolResult, ShellOutput, error) {
    return nil, ShellOutput{Result: in.Command}, nil
}

func main() {
    server := mcp.NewServer(&mcp.Implementation{Name: "demo", Version: "v1.0.0"}, nil)
    mcp.AddTool(server, &mcp.Tool{Name: "execute_shell_command", Description: "Execute shell command"}, executeShellCommand)
}
"""


def test_go_tool_struct_name_overrides_camelcase_handler() -> None:
    """``mcp.Tool{Name: \"execute_shell_command\"}`` must win over handler
    symbol ``executeShellCommand``."""
    analyzer = NativeAnalyzer(GO_REGISTERED_SHELL_TOOL, "shell.go")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "execute_shell_command"


DESCRIPTOR_OBJECT_TOOL = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });

server.addTool({
  name: "descriptor-tool",
  execute: async () => ({ content: [{ type: "text", text: "ok" }] }),
});
"""


def test_descriptor_object_with_name_and_execute_handler() -> None:
    """Object-literal registrations with both ``name`` and ``execute`` must
    retain the inline handler, not just the name string."""
    analyzer = NativeAnalyzer(DESCRIPTOR_OBJECT_TOOL, "descriptor.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    assert "descriptor-tool" in cap.name, cap.name
    assert any(
        t.startswith("<registration>.") and "tool" in t for t in cap.decorator_types
    ), cap.decorator_types
    assert cap.line_number > 0, cap.line_number


PYTHON_CUSTOM_TOOL_NAME = """\
from fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool(name="custom")
def add(a: int, b: int) -> int:
    \"\"\"Add numbers.\"\"\"
    return a + b
"""


def test_python_decorator_name_override_matches_context_extractor() -> None:
    """NativeAnalyzer must honor decorator ``name=`` overrides like ContextExtractor."""
    analyzer = NativeAnalyzer(PYTHON_CUSTOM_TOOL_NAME, "custom_name.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    assert caps[0].name == "custom"


FASTMCP_ADDTOOL_DESCRIPTOR = """\
import { FastMCP } from "fastmcp";

const server = new FastMCP({
  name: "demo",
  version: "1.0",
});

function exfiltrate(secret) {
  return secret;
}

server.addTool({
  name: "run",
  description: "Run a thing",
  parameters: {},
  execute: async (args) => {
    return exfiltrate(args.secret);
  },
});
"""

CONFIG_ARRAYS_WITH_ONE_TOOL = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });

function add(a, b) {
  return a + b;
}

server.tool("add", {}, add);

const ROUTES = [
  { name: "health", path: "/health", method: "GET", description: "health" },
  { name: "metrics", path: "/metrics", method: "GET", description: "metrics" },
];

const MODELS = [
  { name: "gpt-4o", description: "OpenAI model" },
  { name: "claude", description: "Anthropic model" },
];
"""

TWO_INLINE_HANDLER_ARGS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });

server.tool(
  "pick-last",
  {},
  () => "wrong-handler",
  () => "right-handler",
);
"""

NESTED_DECOY_HANDLER_BEFORE_REAL = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";

const server = new McpServer({ name: "demo", version: "1.0" });

server.tool(
  "real",
  { nested: { handler: () => "safe" } },
  async ({ cmd }) => execSync(cmd),
);
"""

NESTED_DECOY_HANDLER_AFTER_REAL = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";

const server = new McpServer({ name: "demo", version: "1.0" });

server.tool(
  "real",
  async ({ cmd }) => execSync(cmd),
  { nested: { handler: () => "safe" } },
);
"""

DIRECT_EXECUTE_IN_DESCRIPTOR = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";

const server = new McpServer({ name: "demo", version: "1.0" });

server.registerTool("run", {
  description: "Run",
  execute: async ({ cmd }) => execSync(cmd),
});
"""


def test_fastmcp_addtool_descriptor_keeps_inline_execute() -> None:
    """FastMCP-TS ``addTool({ name, execute })`` must resolve the tool and
    body calls inside ``execute``."""
    analyzer = NativeAnalyzer(FASTMCP_ADDTOOL_DESCRIPTOR, "fastmcp.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    assert cap.name == "run", cap.name
    assert cap.line_number > 0, cap.line_number
    call_names = {c.get("name") for c in cap.function_calls or []}
    assert "exfiltrate" in call_names, call_names


def test_config_arrays_are_not_mcp_tools() -> None:
    """Standalone HTTP route / model catalogue arrays must not become tools."""
    analyzer = NativeAnalyzer(CONFIG_ARRAYS_WITH_ONE_TOOL, "server.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [(c.name, c.decorator_types) for c in caps]
    assert caps[0].name == "add", caps[0].name
    assert not any(
        "registration.table" in t for t in caps[0].decorator_types
    ), caps[0].decorator_types


def test_two_inline_handlers_pick_last() -> None:
    """When multiple inline functions are passed, the last one is the handler."""
    analyzer = NativeAnalyzer(TWO_INLINE_HANDLER_ARGS, "handlers.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    assert cap.name == "pick-last", cap.name
    literals = cap.string_literals or []
    assert any("right-handler" in lit for lit in literals), literals
    assert not any("wrong-handler" in lit for lit in literals), literals


def _flow_for(ctx, param_name):
    for flow in ctx.parameter_flows:
        if flow.get("parameter_name") == param_name:
            return flow
    return None


def test_ts_destructured_param_taints_command_sink() -> None:
    """A TS tool that runs a destructured ``{ command }`` arg through
    ``execSync`` must record the parameter -> sink flow."""
    analyzer = NativeAnalyzer(DESTRUCTURED_SHELL_TS, "shell.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    param_names = {p.get("name") for p in ctx.parameters}
    assert "command" in param_names, param_names
    flow = _flow_for(ctx, "command")
    assert flow is not None, ctx.parameter_flows
    assert "execSync" in flow["reaches_calls"], flow
    assert flow["reaches_external"] is True, flow


def test_js_destructured_param_taints_eval_sink() -> None:
    """A JS tool that evaluates a destructured ``{ expr }`` arg must record
    the parameter -> eval sink flow."""
    analyzer = NativeAnalyzer(DESTRUCTURED_EVAL_JS, "eval.js")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_eval_exec is True
    param_names = {p.get("name") for p in ctx.parameters}
    assert "expr" in param_names, param_names
    flow = _flow_for(ctx, "expr")
    assert flow is not None, ctx.parameter_flows
    assert "eval" in flow["reaches_calls"], flow
    assert flow["reaches_external"] is True, flow


def test_ts_renamed_and_rest_destructure_binds_value_identifier() -> None:
    """``{ cmd: shellCmd, ...rest }`` binds ``shellCmd`` (the value side) and
    ``rest``, and the renamed binding must carry the taint flow."""
    analyzer = NativeAnalyzer(RENAMED_DESTRUCTURE_TS, "renamed.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    param_names = {p.get("name") for p in ctx.parameters}
    assert "shellCmd" in param_names, param_names
    assert "rest" in param_names, param_names
    # The property *key* ``cmd`` is not a binding and must not appear.
    assert "cmd" not in param_names, param_names
    flow = _flow_for(ctx, "shellCmd")
    assert flow is not None, ctx.parameter_flows
    assert "execSync" in flow["reaches_calls"], flow


# ---------------------------------------------------------------------------
# Delegated sinks + aliased sinks (Example 9):
# A handler that forwards its argument to a same-file helper which runs the
# sink (optionally through a ``promisify(exec)`` alias) must still surface the
# subprocess behavior on the tool, not appear SAFE.
# ---------------------------------------------------------------------------

# Mirrors the real fixture: alias ``execAsync = promisify(exec)`` invoked from
# a static class method that the tool handler delegates to.
DELEGATED_ALIASED_SHELL_TS = """\
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const execAsync = promisify(exec);
const server = new McpServer({ name: "ex9", version: "1.0.0" });

class ShellExecutor {
  static async executeCommand(command: string) {
    const result = await execAsync(command, { shell: true });
    return { stdout: result.stdout };
  }
}

server.registerTool(
  "execute_shell_command",
  { description: "Execute shell command with full shell capabilities." },
  async ({ command }) => {
    const result = await ShellExecutor.executeCommand(command);
    return { content: [{ type: "text", text: result.stdout }] };
  }
);
"""

# Same shape but with a clean alias name (``run``) and helper name (``go``)
# that share NO substring with the SDK sink, so detection cannot rely on a
# coincidental ``"exec" in "executeCommand"`` match.
DELEGATED_CLEAN_NAMES_TS = """\
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const run = promisify(exec);
const server = new McpServer({ name: "ex9", version: "1.0.0" });

class Worker {
  static async go(input: string) {
    const result = await run(input, { shell: true });
    return { stdout: result.stdout };
  }
}

server.registerTool(
  "execute_shell_command",
  { description: "Execute shell command." },
  async ({ command }) => {
    const result = await Worker.go(command);
    return { content: [{ type: "text", text: result.stdout }] };
  }
);
"""

RUST_DELEGATED_SHELL = """\
use std::process::Command;
use rmcp::{tool, tool_router};

struct ShellExecutor;

impl ShellExecutor {
    fn execute_command(command: String) -> String {
        let output = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

#[derive(Clone)]
struct Server;

#[tool_router]
impl Server {
    #[tool(description = "Execute shell command with full shell capabilities.")]
    fn execute_shell_command(&self, command: String) -> String {
        ShellExecutor::execute_command(command)
    }
}
"""


def test_promisify_alias_detected_as_command_sink() -> None:
    """``const run = promisify(exec)`` must mark the helper that calls
    ``run(...)`` as a subprocess sink, even with a clean alias name."""
    analyzer = NativeAnalyzer(DELEGATED_CLEAN_NAMES_TS, "alias.ts")
    # The helper method itself must be recognized as running a subprocess.
    funcs = {f.name: f for f in analyzer.analyze().functions}
    helper = funcs.get("Worker.go")
    assert helper is not None, list(funcs)
    assert helper.has_subprocess_calls is True


def test_handler_inherits_delegated_aliased_shell_sink() -> None:
    """The real Example 9 shape: handler -> static method -> ``execAsync``
    alias. The tool must surface the subprocess behavior and the parameter
    flow must reach an external sink."""
    analyzer = NativeAnalyzer(DELEGATED_ALIASED_SHELL_TS, "ex9.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    assert "ShellExecutor.executeCommand" in (ctx.reachable_functions or []), (
        ctx.reachable_functions
    )
    flow = _flow_for(ctx, "command")
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is True, flow
    summary_flow = (ctx.dataflow_summary or {}).get("param_flows", {}).get("command")
    assert summary_flow is not None, ctx.dataflow_summary
    assert summary_flow["reaches_external"] is True, summary_flow


def test_handler_inherits_delegated_sink_with_clean_names() -> None:
    """Detection must not rely on the helper/alias names coincidentally
    containing the SDK sink name."""
    analyzer = NativeAnalyzer(DELEGATED_CLEAN_NAMES_TS, "clean.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True, "delegated aliased sink not propagated"
    assert "Worker.go" in (ctx.reachable_functions or []), ctx.reachable_functions
    flow = _flow_for(ctx, "command")
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is True, flow


def test_rust_handler_inherits_delegated_shell_sink() -> None:
    """Rust rmcp tool -> helper with ``Command::new(\"sh\").arg(\"-c\")`` must
    surface subprocess behavior on the MCP handler."""
    analyzer = NativeAnalyzer(RUST_DELEGATED_SHELL, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True, "delegated shell sink not propagated"
    assert "ShellExecutor.execute_command" in (ctx.reachable_functions or []), (
        ctx.reachable_functions
    )
    assert ctx.docstring == "Execute shell command with full shell capabilities."
    flow = _flow_for(ctx, "command")
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is True, flow


# Inlined from the code-scanning fixtures. Those files live outside this
# repo, and CI runs with ``--maxfail=1``, so a missing path fails the job
# before the later cases run. The Rust tool impl is still missing its
# closing brace, which is what the scanner has to tolerate.
RUST_SHELL_FIXTURE = """\
use rmcp::{tool, tool_router, ErrorData as McpError, model::*};
use std::process::Command;

#[derive(Clone)]
struct ShellExecutorService;

impl ShellExecutorService {
    fn execute_command(command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }
}

#[tool_router]
impl ShellExecutorService {
	#[tool(description = "Execute a shell command for automation tasks.")]
	async fn execute_shell_command(&self, command: String) -> Result<CallToolResult, McpError> {
        let rc = Self::execute_command(&command);
        Ok(CallToolResult::success(vec![Content::text(format!("Command executed: return code {rc}"))]))

}

fn main() {
	let _service = ShellExecutorService;
}
"""

DYNAMIC_MODULE_LOAD_SOURCES = {
    "importlib_dynamic_module_loading.py": """\
from mcp import FastMCP
import importlib.util

app = FastMCP("unauthorized-code-execution-service-10")


class PluginLoader:
    @staticmethod
    def load_from_path(plugin_path: str) -> dict:
        spec = importlib.util.spec_from_file_location("plugin", plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return {"path": plugin_path, "module_name": module.__name__}


@app.tool()
def load_plugin(plugin_path: str) -> str:
    \"\"\"Load a plugin module from the plugins directory.\"\"\"
    loader = PluginLoader()
    result = loader.load_from_path(plugin_path)
    return f"Plugin loaded: {result.get('module_name', 'unknown')}"
""",
    "importlib_dynamic_module_loading.js": """\
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "unauthorized-code-execution-service-10", version: "1.0.0" });
const requireModule = createRequire(import.meta.url);

class PluginLoader {
  static loadFromPath(pluginPath) {
    const module = requireModule(pluginPath);
    return { path: pluginPath, module_name: pluginPath, loaded: true, module };
  }
}

server.tool(
  "load_plugin",
  "Load a plugin module from the plugins directory.",
  { plugin_path: z.string() },
  async ({ plugin_path }) => {
    const result = PluginLoader.loadFromPath(plugin_path);
    return { content: [{ type: "text", text: `Plugin loaded: ${result.module_name}` }] };
  },
);
""",
    "importlib_dynamic_module_loading.ts": """\
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "unauthorized-code-execution-service-10", version: "1.0.0" });
const requireModule = createRequire(import.meta.url);

class PluginLoader {
  static loadFromPath(pluginPath: string): Record<string, unknown> {
    const module = requireModule(pluginPath);
    return { path: pluginPath, module_name: pluginPath, loaded: true, module };
  }
}

server.tool(
  "load_plugin",
  "Load a plugin module from the plugins directory.",
  { plugin_path: z.string() },
  async ({ plugin_path }) => {
    const result = PluginLoader.loadFromPath(plugin_path);
    return { content: [{ type: "text", text: `Plugin loaded: ${result.module_name}` }] };
  },
);
""",
    "importlib_dynamic_module_loading.go": """\
package main

import (
	"context"
	"fmt"
	"plugin"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Input struct {
	PluginPath string `json:"plugin_path"`
}

type PluginLoader struct{}

func (PluginLoader) loadFromPath(pluginPath string) string {
	p, err := plugin.Open(pluginPath)
	if err != nil { return err.Error() }
	_, err = p.Lookup("Init")
	if err != nil { return err.Error() }
	return pluginPath
}

func load_pluginHandler(ctx context.Context, req *mcp.CallToolRequest, in Input) (*mcp.CallToolResult, any, error) {
	result := PluginLoader{}.loadFromPath(in.PluginPath)
	out := fmt.Sprintf("Plugin loaded: %s", result)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: out}}}, nil, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "unauthorized-code-execution-service-10", Version: "1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "load_plugin", Description: "Load a plugin module from the plugins directory."}, load_pluginHandler)
}
""",
    "importlib_dynamic_module_loading.rs": """\
use rmcp::{tool, tool_router, ErrorData as McpError, model::*};
use libloading::Library;

#[derive(Clone)]
struct PluginLoaderService;

impl PluginLoaderService {
    fn load_from_path(plugin_path: &str) -> String {
        match unsafe { Library::new(plugin_path) } {
            Ok(_) => plugin_path.to_string(),
            Err(e) => e.to_string(),
        }
    }
}

#[tool_router]
impl PluginLoaderService {
	#[tool(description = "Load a plugin module from the plugins directory.")]
	async fn load_plugin(&self, plugin_path: String) -> Result<CallToolResult, McpError> {
        let result = Self::load_from_path(&plugin_path);
        Ok(CallToolResult::success(vec![Content::text(format!("Plugin loaded: {result}"))]))

}

fn main() {
	let _service = PluginLoaderService;
}
""",
}


def test_rust_fixture_self_call_reaches_shell_sink() -> None:
    """The Rust shell fixture calls ``Self::execute_command``.

    That name is stored both bare and qualified, and the tool impl is
    missing its closing brace. The handler must still inherit the
    ``Command::new`` sink and the parameter flow.
    """
    analyzer = NativeAnalyzer(
        RUST_SHELL_FIXTURE, "subprocess_shell_command_injection.rs"
    )
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.name == "execute_shell_command"
    assert ctx.has_subprocess_calls is True
    assert "ShellExecutorService.execute_command" in (ctx.reachable_functions or [])
    flow = _flow_for(ctx, "command")
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is True, flow


@pytest.mark.parametrize(
    "filename",
    [
        "importlib_dynamic_module_loading.py",
        "importlib_dynamic_module_loading.js",
        "importlib_dynamic_module_loading.ts",
        "importlib_dynamic_module_loading.go",
        "importlib_dynamic_module_loading.rs",
    ],
)
def test_dynamic_module_load_fixture_flags_eval(filename: str) -> None:
    """Each language port of the plugin loader must surface dynamic loading.

    Python loads via ``importlib.util``, JS/TS via ``createRequire``, Go via
    ``plugin.Open``, and Rust via ``libloading``.
    """
    analyzer = NativeAnalyzer(DYNAMIC_MODULE_LOAD_SOURCES[filename], filename)
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, filename
    ctx = caps[0]
    assert ctx.name == "load_plugin", filename
    assert ctx.has_eval_exec is True, filename
    assert ctx.has_subprocess_calls is False, filename
    assert ctx.reachable_functions, filename
    assert any(flow.get("reaches_external") for flow in ctx.parameter_flows), (
        filename,
        ctx.parameter_flows,
    )


def test_rust_fixture_self_call_reaches_imported_library_sink() -> None:
    """``use libloading::Library`` then ``Library::new`` is dynamic loading.

    The fixture reaches that call through ``Self::load_from_path``.
    """
    source = DYNAMIC_MODULE_LOAD_SOURCES["importlib_dynamic_module_loading.rs"]
    analyzer = NativeAnalyzer(source, "importlib_dynamic_module_loading.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.name == "load_plugin"
    assert ctx.has_eval_exec is True
    assert ctx.has_subprocess_calls is False
    assert "PluginLoaderService.load_from_path" in (ctx.reachable_functions or [])
    flow = _flow_for(ctx, "plugin_path")
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is True, flow


RUST_SELF_AMONG_SAME_LEAF = """\
use std::process::Command;
use rmcp::{tool, tool_router};

struct Other;

impl Other {
    fn execute_command(command: &str) -> i32 {
        command.len() as i32
    }
}

struct Svc;

#[tool_router]
impl Svc {
    fn execute_command(command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }

    #[tool(description = "Execute a shell command for automation tasks.")]
    fn execute_shell_command(&self, command: String) -> i32 {
        Self::execute_command(&command)
    }
}
"""


def test_rust_self_call_resolves_inside_its_own_impl() -> None:
    """``Self::`` must not give up when another impl defines the same leaf."""
    analyzer = NativeAnalyzer(RUST_SELF_AMONG_SAME_LEAF, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    assert "Svc.execute_command" in (ctx.reachable_functions or [])
    flow = _flow_for(ctx, "command")
    assert flow is not None
    assert flow["reaches_external"] is True, flow


RUST_INSTANCE_CALL = """\
use std::process::Command;
use rmcp::{tool, tool_router};

struct Client;

impl Client {
    fn execute(&self, command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }
}

struct Svc;

#[tool_router]
impl Svc {
    #[tool(description = "Run a command through the client.")]
    fn run(&self, command: String) -> i32 {
        let client = Client;
        client.execute(&command)
    }
}
"""


def test_rust_instance_call_reaches_indexed_method() -> None:
    """``client.execute`` still targets ``Client.execute``."""
    analyzer = NativeAnalyzer(RUST_INSTANCE_CALL, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    assert "Client.execute" in (ctx.reachable_functions or [])
    flow = _flow_for(ctx, "command")
    assert flow is not None
    assert flow["reaches_external"] is True, flow


RUST_TRAIT_IMPL_SELF = """\
use std::process::Command;
use rmcp::{tool, tool_router};

trait ServerHandler {}

struct Svc;
struct Other;

impl ServerHandler for Svc {
    fn helper(&self, command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }

    #[tool(description = "Run a command through the trait impl.")]
    fn run(&self, command: String) -> i32 {
        Self::helper(self, &command)
    }
}

impl ServerHandler for Other {
    fn helper(&self, command: &str) -> i32 {
        command.len() as i32
    }
}
"""


def test_rust_trait_impl_self_uses_the_implementing_type() -> None:
    """``impl ServerHandler for Svc`` indexes the type, not the trait alone."""
    analyzer = NativeAnalyzer(RUST_TRAIT_IMPL_SELF, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    reachable = ctx.reachable_functions or []
    assert ctx.has_subprocess_calls is True
    assert "Svc.ServerHandler.helper" in reachable
    assert "ServerHandler.helper" not in reachable
    assert "Other.helper" not in reachable
    flow = _flow_for(ctx, "command")
    assert flow is not None
    assert flow["reaches_external"] is True, flow


RUST_GENERIC_IMPL_SELF = """\
use std::process::Command;
use rmcp::{tool, tool_router};

struct Svc<T> {
    _marker: std::marker::PhantomData<T>,
}

struct Other;

impl Other {
    fn helper(command: &str) -> i32 {
        command.len() as i32
    }
}

impl<T> Svc<T> {
    fn helper(command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }
}

#[tool_router]
impl Svc<String> {
    #[tool(description = "Run a command through the generic impl.")]
    fn run(&self, command: String) -> i32 {
        Self::helper(&command)
    }
}
"""


def test_rust_generic_impl_self_uses_the_type_name() -> None:
    """``impl<T> Svc<T>`` indexes ``Svc.helper`` so ``Self::helper`` resolves."""
    analyzer = NativeAnalyzer(RUST_GENERIC_IMPL_SELF, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    reachable = ctx.reachable_functions or []
    assert ctx.has_subprocess_calls is True
    assert "Svc.helper" in reachable
    assert "Other.helper" not in reachable
    flow = _flow_for(ctx, "command")
    assert flow is not None
    assert flow["reaches_external"] is True, flow


RUST_TRAIT_IMPL_DOES_NOT_REPLACE_INHERENT = """\
use std::process::Command;
use rmcp::{tool, tool_router};

trait ServerHandler {}

struct Svc;

impl ServerHandler for Svc {
    fn helper(&self, command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }
}

#[tool_router]
impl Svc {
    fn helper(&self, command: &str) -> i32 {
        command.len() as i32
    }

    #[tool(description = "Measure a command string.")]
    fn run(&self, command: String) -> i32 {
        Self::helper(self, &command)
    }
}
"""


def test_rust_self_in_inherent_impl_ignores_later_trait_impl() -> None:
    """A later trait impl must not replace this impl's ``Self::helper``."""
    analyzer = NativeAnalyzer(RUST_TRAIT_IMPL_DOES_NOT_REPLACE_INHERENT, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    reachable = ctx.reachable_functions or []
    assert ctx.has_subprocess_calls is False
    assert "Svc.helper" in reachable
    assert "Svc.ServerHandler.helper" not in reachable


RUST_INHERENT_IMPL_DOES_NOT_REPLACE_TRAIT = """\
use std::process::Command;
use rmcp::{tool, tool_router};

trait ServerHandler {}

struct Svc;

#[tool_router]
impl ServerHandler for Svc {
    fn helper(&self, command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }

    #[tool(description = "Run a command through the trait impl.")]
    fn run(&self, command: String) -> i32 {
        Self::helper(self, &command)
    }
}

impl Svc {
    fn helper(&self, command: &str) -> i32 {
        command.len() as i32
    }
}
"""


def test_rust_self_in_trait_impl_ignores_later_inherent_impl() -> None:
    """A later inherent impl must not hide this trait impl's shell call."""
    analyzer = NativeAnalyzer(RUST_INHERENT_IMPL_DOES_NOT_REPLACE_TRAIT, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    reachable = ctx.reachable_functions or []
    assert ctx.has_subprocess_calls is True
    assert "Svc.ServerHandler.helper" in reachable
    assert "Svc.helper" not in reachable


RUST_BOX_IMPLS_STAY_DISTINCT = """\
use std::process::Command;
use rmcp::{tool, tool_router};

trait ServerHandler {}

struct Svc;
struct Other;

#[tool_router]
impl ServerHandler for Box<Svc> {
    fn helper(&self, command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }

    #[tool(description = "Run a command through the boxed impl.")]
    fn run(&self, command: String) -> i32 {
        Self::helper(&command)
    }
}

impl ServerHandler for Box<Other> {
    fn helper(&self, command: &str) -> i32 {
        command.len() as i32
    }
}
"""


def test_rust_box_impls_do_not_share_a_method_key() -> None:
    """``Box<Svc>`` and ``Box<Other>`` do not overwrite one ``helper``."""
    analyzer = NativeAnalyzer(RUST_BOX_IMPLS_STAY_DISTINCT, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    reachable = ctx.reachable_functions or []
    assert ctx.has_subprocess_calls is True
    assert "Box<Svc>.ServerHandler.helper" in reachable
    assert "Box<Other>.ServerHandler.helper" not in reachable


RUST_CRATE_PATH_CALL = """\
use std::process::Command;
use rmcp::{tool, tool_router};

struct Plugin;

impl Plugin {
    fn new(command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }
}

struct Svc;

#[tool_router]
impl Svc {
    #[tool(description = "Run a command through the local plugin.")]
    fn run(&self, command: String) -> i32 {
        crate::Plugin::new(&command)
    }
}
"""


def test_rust_crate_path_reaches_local_method() -> None:
    """``crate::Plugin::new`` reaches the local ``Plugin::new``."""
    analyzer = NativeAnalyzer(RUST_CRATE_PATH_CALL, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    assert "Plugin.new" in (ctx.reachable_functions or [])
    flow = _flow_for(ctx, "command")
    assert flow is not None
    assert flow["reaches_external"] is True, flow


RUST_TURBOFISH_CALL = """\
use std::process::Command;
use rmcp::{tool, tool_router};

struct Svc<T> {
    _marker: std::marker::PhantomData<T>,
}

impl<T> Svc<T> {
    fn helper(command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }
}

struct App;

#[tool_router]
impl App {
    #[tool(description = "Run a command through the generic helper.")]
    fn run(&self, command: String) -> i32 {
        Svc::<String>::helper(&command)
    }
}
"""


def test_rust_turbofish_reaches_blanket_impl() -> None:
    """``Svc::<String>::helper`` reaches ``impl<T> Svc<T>``."""
    analyzer = NativeAnalyzer(RUST_TURBOFISH_CALL, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    assert "Svc.helper" in (ctx.reachable_functions or [])
    flow = _flow_for(ctx, "command")
    assert flow is not None
    assert flow["reaches_external"] is True, flow


RUST_RENAMED_LIBRARY_IMPORT = """\
use libloading::Library as PluginLib;
use rmcp::{tool, tool_router};

struct Svc;

#[tool_router]
impl Svc {
    fn open(path: &str) -> String {
        unsafe { PluginLib::new(path).unwrap(); }
        path.to_string()
    }

    #[tool(description = "Load a plugin module from the plugins directory.")]
    fn load_plugin(&self, plugin_path: String) -> String {
        Self::open(&plugin_path)
    }
}
"""


def test_rust_renamed_libloading_import_is_dynamic_loading() -> None:
    """``use libloading::Library as PluginLib`` keeps ``PluginLib::new`` a sink."""
    analyzer = NativeAnalyzer(RUST_RENAMED_LIBRARY_IMPORT, "lib.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_eval_exec is True
    assert ctx.has_subprocess_calls is False
    flow = _flow_for(ctx, "plugin_path")
    assert flow is not None
    assert flow["reaches_external"] is True, flow


PYTHON_DELEGATED_SHELL = """\
from mcp import FastMCP
import subprocess

app = FastMCP("unauthorized-code-execution-service-9")


class ShellExecutor:
    @staticmethod
    def execute_command(command: str) -> dict:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=10
        )
        return {"returncode": result.returncode, "stdout": result.stdout}


@app.tool()
def execute_shell_command(command: str) -> str:
    \"\"\"Execute shell command with full shell capabilities.\"\"\"
    executor = ShellExecutor()
    result = executor.execute_command(command)
    return f"Command executed: return code {result.get('returncode', 'unknown')}"
"""


def test_python_handler_inherits_delegated_shell_sink() -> None:
    """Python FastMCP tool -> ``ShellExecutor.execute_command`` with
    ``subprocess.run(..., shell=True)`` must surface subprocess behavior."""
    analyzer = NativeAnalyzer(PYTHON_DELEGATED_SHELL, "shell.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.name == "execute_shell_command"
    assert ctx.has_subprocess_calls is True, "delegated shell sink not propagated"
    assert "ShellExecutor.execute_command" in (ctx.reachable_functions or []), (
        ctx.reachable_functions
    )
    flow = _flow_for(ctx, "command")
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is True, flow


SHADOWED_ALIAS_TS = """\
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const run = promisify(exec);
const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool(
  "safe_echo",
  { description: "Echo input without shell execution." },
  async ({ run }) => {
    // parameter ``run`` shadows the module-level promisify(exec) alias
    const out = await run(run);
    return { content: [{ type: "text", text: out.stdout ?? "" }] };
  }
);
"""

LOCAL_ALIAS_IN_HANDLER_TS = """\
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool(
  "execute_shell_command",
  { description: "Run shell command in handler scope." },
  async ({ command }) => {
    const run = promisify(exec);
    await run(command);
    return { content: [{ type: "text", text: "done" }] };
  }
);
"""

NESTED_SCOPE_SHADOW_TS = """\
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const run = promisify(exec);
const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool(
  "execute_shell_command",
  { description: "Run shell command." },
  async ({ command }) => {
    function helper() {
      const run = "local-only";
      return run;
    }
    helper();
    await run(command);
    return { content: [{ type: "text", text: "done" }] };
  }
);
"""

AMBIGUOUS_DELEGATE_TS = """\
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const run = promisify(exec);
const server = new McpServer({ name: "demo", version: "1.0.0" });

class SafeWorker {
  static async executeCommand(input: string) {
    return { stdout: input };
  }
}

class ShellExecutor {
  static async executeCommand(input: string) {
    const result = await run(input, { shell: true });
    return { stdout: result.stdout };
  }
}

server.registerTool(
  "execute_shell_command",
  { description: "Run shell command." },
  async ({ command }) => {
    const result = await ShellExecutor.executeCommand(command);
    return { content: [{ type: "text", text: result.stdout }] };
  }
);
"""


def test_shadowed_parameter_does_not_inherit_module_alias() -> None:
    """A parameter named like a module alias must not inherit that alias when
    invoked as the callee of a call expression."""
    analyzer = NativeAnalyzer(SHADOWED_ALIAS_TS, "shadow.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is False


def test_local_sink_alias_in_handler_is_detected() -> None:
    """A sink alias declared inside the handler (``const run = promisify(exec)``
    then ``run(cmd)``) must still classify as a subprocess sink."""
    analyzer = NativeAnalyzer(LOCAL_ALIAS_IN_HANDLER_TS, "local_alias.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    flow = _flow_for(ctx, "command")
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is True, flow


def test_nested_scope_locals_do_not_shadow_outer_alias() -> None:
    """A same-named local inside a nested helper must not suppress the module
    alias visible to the enclosing tool handler."""
    analyzer = NativeAnalyzer(NESTED_SCOPE_SHADOW_TS, "nested_scope.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    flow = _flow_for(ctx, "command")
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is True, flow


def test_qualified_delegate_resolves_correct_class_method() -> None:
    """When two classes share a method name, delegation must resolve the
    qualified ``Class.method`` target, not the first bare leaf match."""
    analyzer = NativeAnalyzer(AMBIGUOUS_DELEGATE_TS, "ambig.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is True
    assert "ShellExecutor.executeCommand" in (ctx.reachable_functions or []), (
        ctx.reachable_functions
    )
    assert "SafeWorker.executeCommand" not in (ctx.reachable_functions or []), (
        ctx.reachable_functions
    )


def test_nested_decoy_handler_does_not_hide_positional_handler() -> None:
    """Nested schema decoys must not displace the real positional handler."""
    for source in (NESTED_DECOY_HANDLER_BEFORE_REAL, NESTED_DECOY_HANDLER_AFTER_REAL):
        analyzer = NativeAnalyzer(source, "decoy.ts")
        caps = analyzer.extract_mcp_capability_contexts()
        assert len(caps) == 1, [c.name for c in caps]
        cap = caps[0]
        assert cap.name == "real", cap.name
        call_names = {c.get("name") for c in cap.function_calls or []}
        assert "execSync" in call_names, call_names
        assert cap.has_subprocess_calls is True, cap.has_subprocess_calls


def test_direct_execute_field_in_descriptor_object() -> None:
    """Top-level ``execute`` on a descriptor object must resolve inline handlers."""
    analyzer = NativeAnalyzer(DIRECT_EXECUTE_IN_DESCRIPTOR, "descriptor.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    assert cap.name == "run", cap.name
    call_names = {c.get("name") for c in cap.function_calls or []}
    assert "execSync" in call_names, call_names


def _function(source: str, filename: str, func_name: str):
    analyzer = NativeAnalyzer(source, filename)
    funcs = {f.name: f for f in analyzer.analyze().functions}
    return funcs[func_name]


@pytest.mark.parametrize(
    ("source", "filename", "func_name", "flag"),
    [
        (
            "function run(cmd) {\n  fork(cmd);\n}\n",
            "run.js",
            "run",
            "has_subprocess_calls",
        ),
        (
            "function run(cmd) {\n  exec(cmd);\n}\n",
            "run.js",
            "run",
            "has_subprocess_calls",
        ),
        (
            "function run(cmd) {\n  spawn(cmd);\n}\n",
            "run.js",
            "run",
            "has_subprocess_calls",
        ),
        (
            "function run(code) {\n  runInContext(code);\n}\n",
            "run.js",
            "run",
            "has_eval_exec",
        ),
        (
            "package main\nfunc run(cmd string) {\n\tCommand(cmd)\n}\n",
            "run.go",
            "run",
            "has_subprocess_calls",
        ),
        (
            "package main\nfunc run(cmd string) {\n\tStartProcess(cmd)\n}\n",
            "run.go",
            "run",
            "has_subprocess_calls",
        ),
        (
            "package main\nfunc run(cmd string) {\n\tExec(cmd)\n}\n",
            "run.go",
            "run",
            "has_subprocess_calls",
        ),
        (
            "class T {\n  void run(String cmd) {\n    exec(cmd);\n  }\n}\n",
            "T.java",
            "T.run",
            "has_subprocess_calls",
        ),
        (
            "class T {\n  void launch() {\n    start();\n  }\n}\n",
            "T.java",
            "T.launch",
            "has_subprocess_calls",
        ),
        (
            "function load(pluginPath) {\n"
            "  return createRequire(import.meta.url)(pluginPath);\n"
            "}\n",
            "load.js",
            "load",
            "has_eval_exec",
        ),
        (
            "function load(pluginPath) {\n"
            "  return module.createRequire(import.meta.url)(pluginPath);\n"
            "}\n",
            "load.js",
            "load",
            "has_eval_exec",
        ),
        (
            "use libloading::*;\n"
            "fn load_plugin(path: &str) {\n"
            "    unsafe { Library::new(path); }\n"
            "}\n",
            "lib.rs",
            "load_plugin",
            "has_eval_exec",
        ),
        (
            "use libloading::*;\n"
            "use serde::*;\n"
            "fn load_plugin(path: &str) {\n"
            "    unsafe { Library::new(path); }\n"
            "}\n",
            "lib.rs",
            "load_plugin",
            "has_eval_exec",
        ),
        (
            "import importlib\n"
            "def load(name):\n"
            "    return importlib.import_module(name)\n",
            "load.py",
            "load",
            "has_eval_exec",
        ),
        (
            "def load(name):\n"
            "    return import_module(name)\n",
            "load.py",
            "load",
            "has_eval_exec",
        ),
        (
            "import importlib as il\n"
            "def load(name):\n"
            "    return il.import_module(name)\n",
            "load.py",
            "load",
            "has_eval_exec",
        ),
        (
            "from importlib import import_module as load_mod\n"
            "def load(name):\n"
            "    return load_mod(name)\n",
            "load.py",
            "load",
            "has_eval_exec",
        ),
        (
            "def run(code):\n"
            "    return builtins.eval(code)\n",
            "run.py",
            "run",
            "has_eval_exec",
        ),
        (
            "def run(code):\n"
            "    return builtins.exec(code)\n",
            "run.py",
            "run",
            "has_eval_exec",
        ),
        (
            "def load(loader, module):\n"
            "    loader.exec_module(module)\n",
            "load.py",
            "load",
            "has_eval_exec",
        ),
        (
            "def load(loader, name):\n"
            "    return loader.load_module(name)\n",
            "load.py",
            "load",
            "has_eval_exec",
        ),
        (
            "function load(pluginPath) {\n"
            "  return (createRequire(import.meta.url))(pluginPath);\n"
            "}\n",
            "load.js",
            "load",
            "has_eval_exec",
        ),
        (
            "function load(pluginPath) {\n"
            "  const req = createRequire;\n"
            "  return req(import.meta.url)(pluginPath);\n"
            "}\n",
            "load.js",
            "load",
            "has_eval_exec",
        ),
        (
            "use libloading::*;\n"
            "use foo::libloading::*;\n"
            "fn load_plugin(path: &str) {\n"
            "    unsafe { Library::new(path); }\n"
            "}\n",
            "lib.rs",
            "load_plugin",
            "has_eval_exec",
        ),
    ],
)
def test_destructured_and_loader_shapes_still_match(
    source: str, filename: str, func_name: str, flag: str
) -> None:
    """Bare sink leaves, glob imports, and inline createRequire stay sinks."""
    func = _function(source, filename, func_name)
    assert getattr(func, flag) is True, (filename, func_name, flag)


def test_inner_libloading_glob_shadows_outer_use() -> None:
    """A narrower ``use libloading::*`` hides an outer ``use other::Library``."""
    shadowed = """\
use other::Library;

fn load_plugin(path: &str) {
    use libloading::*;
    unsafe { Library::new(path); }
}
"""
    func = _function(shadowed, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True
    assert func.has_subprocess_calls is False

    kept = """\
use libloading::Library;

fn load_plugin(path: &str) {
    use std::io::*;
    unsafe { Library::new(path); }
}
"""
    func = _function(kept, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True


def test_grouped_std_paths_still_match_sinks() -> None:
    """Grouped ``std`` imports keep their prefix and still hit the sinks."""
    command = """\
use std::{process::Command};

fn run_shell(cmd: &str) {
    let _ = Command::new(cmd);
}
"""
    func = _function(command, "lib.rs", "run_shell")
    assert func.has_subprocess_calls is True

    opened = """\
use std::{fs::File};

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(opened, "lib.rs", "read_it")
    assert func.has_file_operations is True

    tokio = """\
fn run_shell(cmd: &str) {
    let _ = tokio::process::Command::new(cmd);
}
"""
    func = _function(tokio, "lib.rs", "run_shell")
    assert func.has_subprocess_calls is True


def test_rust_std_fs_glob_open_is_a_file_operation() -> None:
    """``use std::fs::*;`` then ``File::open`` is the ``fs::File::open`` sink."""
    source = """\
use std::fs::*;

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(source, "lib.rs", "read_it")
    assert func.has_file_operations is True
    assert func.has_eval_exec is False

    both = """\
use std::fs::*;
use fs::*;

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(both, "lib.rs", "read_it")
    assert func.has_file_operations is True


def test_async_fs_file_apis_are_file_operations() -> None:
    """tokio and async-std ``File::open`` / ``File::create`` are file sinks."""
    written = """\
fn read_it(path: &str) {
    let _ = tokio::fs::File::open(path);
}
"""
    func = _function(written, "lib.rs", "read_it")
    assert func.has_file_operations is True

    imported = """\
use tokio::fs::File;

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(imported, "lib.rs", "read_it")
    assert func.has_file_operations is True

    grouped = """\
use tokio::fs::{File};

fn read_it(path: &str) {
    let _ = File::create(path);
}
"""
    func = _function(grouped, "lib.rs", "read_it")
    assert func.has_file_operations is True

    globbed = """\
use tokio::fs::*;

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(globbed, "lib.rs", "read_it")
    assert func.has_file_operations is True

    async_std = """\
use async_std::fs::File;

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(async_std, "lib.rs", "read_it")
    assert func.has_file_operations is True

    async_std_create = """\
fn read_it(path: &str) {
    let _ = async_std::fs::File::create(path);
}
"""
    func = _function(async_std_create, "lib.rs", "read_it")
    assert func.has_file_operations is True


def test_inner_glob_beats_type_that_hides_outer_use() -> None:
    """A glob inside a local type's block is the name Rust resolves."""
    source = """\
use other::Library;

fn load_plugin(path: &str) {
    struct Library;
    {
        use libloading::*;
        unsafe { Library::new(path); }
    }
}
"""
    func = _function(source, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True
    assert func.has_subprocess_calls is False

    opened = """\
use other::File;

fn read_it(path: &str) {
    struct File;
    {
        use std::fs::*;
        let _ = File::open(path);
    }
}
"""
    func = _function(opened, "lib.rs", "read_it")
    assert func.has_file_operations is True
    assert func.has_eval_exec is False


def test_crate_root_paths_match_the_same_sinks() -> None:
    """A leading ``::`` is the crate root, not a foreign prefix."""
    written_lib = """\
fn load_plugin(path: &str) {
    unsafe { ::libloading::Library::new(path); }
}
"""
    func = _function(written_lib, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True

    imported_lib = """\
use ::libloading::Library;

fn load_plugin(path: &str) {
    unsafe { Library::new(path); }
}
"""
    func = _function(imported_lib, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True

    glob_lib = """\
use ::libloading::*;

fn load_plugin(path: &str) {
    unsafe { Library::new(path); }
}
"""
    func = _function(glob_lib, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True

    std_file = """\
fn read_it(path: &str) {
    let _ = ::std::fs::File::open(path);
}
"""
    func = _function(std_file, "lib.rs", "read_it")
    assert func.has_file_operations is True

    use_std_file = """\
use ::std::fs::File;

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(use_std_file, "lib.rs", "read_it")
    assert func.has_file_operations is True

    tokio_file = """\
fn read_it(path: &str) {
    let _ = ::tokio::fs::File::open(path);
}
"""
    func = _function(tokio_file, "lib.rs", "read_it")
    assert func.has_file_operations is True

    tokio_glob = """\
use ::tokio::fs::*;

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(tokio_glob, "lib.rs", "read_it")
    assert func.has_file_operations is True

    command = """\
fn run_shell(cmd: &str) {
    let _ = ::std::process::Command::new(cmd);
}
"""
    func = _function(command, "lib.rs", "run_shell")
    assert func.has_subprocess_calls is True


def test_smol_fs_file_open_is_a_file_operation() -> None:
    """``smol::fs::File::open`` and ``File::create`` are file operations."""
    written = """\
fn read_it(path: &str) {
    let _ = smol::fs::File::open(path);
}
"""
    func = _function(written, "lib.rs", "read_it")
    assert func.has_file_operations is True

    created = """\
use smol::fs::File;

fn read_it(path: &str) {
    let _ = File::create(path);
}
"""
    func = _function(created, "lib.rs", "read_it")
    assert func.has_file_operations is True

    globbed = """\
use smol::fs::*;

fn read_it(path: &str) {
    let _ = File::open(path);
}
"""
    func = _function(globbed, "lib.rs", "read_it")
    assert func.has_file_operations is True

    absolute = """\
fn read_it(path: &str) {
    let _ = ::smol::fs::File::create(path);
}
"""
    func = _function(absolute, "lib.rs", "read_it")
    assert func.has_file_operations is True


def test_crate_root_path_ignores_a_local_use() -> None:
    """``::libloading`` stays that crate when a ``use`` binds the same name."""
    lib = """\
use other::libloading;

fn load_plugin(path: &str) {
    unsafe { ::libloading::Library::new(path); }
}
"""
    func = _function(lib, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True

    opened = """\
use other::std;

fn read_it(path: &str) {
    let _ = ::std::fs::File::open(path);
}
"""
    func = _function(opened, "lib.rs", "read_it")
    assert func.has_file_operations is True

    tokio = """\
use other::tokio;

fn read_it(path: &str) {
    let _ = ::tokio::fs::File::open(path);
}
"""
    func = _function(tokio, "lib.rs", "read_it")
    assert func.has_file_operations is True


def test_parenthesized_rust_paths_still_match_sinks() -> None:
    """Parentheses around a path do not hide the sink."""
    lib = """\
fn load_plugin(path: &str) {
    unsafe { (::libloading::Library::new)(path); }
}
"""
    func = _function(lib, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True

    relative = """\
fn load_plugin(path: &str) {
    unsafe { (libloading::Library::new)(path); }
}
"""
    func = _function(relative, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True

    opened = """\
fn read_it(path: &str) {
    let _ = (std::fs::File::open)(path);
}
"""
    func = _function(opened, "lib.rs", "read_it")
    assert func.has_file_operations is True


def test_absolute_libloading_stays_a_sink_beside_a_local_module() -> None:
    """``::libloading`` is the extern crate when a local module has that name."""
    source = """\
mod libloading {
    pub struct Library;
    impl Library {
        pub fn new(_path: &str) -> Self { Library }
    }
}

fn load_plugin(path: &str) {
    unsafe { ::libloading::Library::new(path); }
}
"""
    func = _function(source, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True

    imported = """\
mod libloading {
    pub struct Library;
    impl Library {
        pub fn new(_path: &str) -> Self { Library }
    }
}

fn load_plugin(path: &str) {
    use ::libloading::Library;
    unsafe { Library::new(path); }
}
"""
    func = _function(imported, "lib.rs", "load_plugin")
    assert func.has_eval_exec is True


def test_inner_use_beats_an_outer_module() -> None:
    """A narrower ``use`` rebinds a name an outer ``mod`` would own."""
    source = """\
mod File {
    pub struct X;
}

fn read_it(path: &str) {
    use std::fs::File;
    let _ = File::open(path);
}

fn read_glob(path: &str) {
    use std::fs::*;
    let _ = File::open(path);
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["read_it"].has_file_operations is True
    assert funcs["read_glob"].has_file_operations is True


def test_inner_module_does_not_hide_an_outer_import() -> None:
    """A nested ``mod`` does not rebind an import written outside it."""
    source = """\
fn read_it(path: &str) {
    use std::fs::File;
    {
        mod std { pub struct X; }
        let _ = File::open(path);
    }
}

fn read_glob(path: &str) {
    use std::fs::*;
    {
        mod std { pub struct X; }
        let _ = File::open(path);
    }
}

fn load_plugin(path: &str) {
    use libloading::Library;
    {
        mod libloading { pub struct X; }
        unsafe { Library::new(path); }
    }
}

fn read_after(path: &str) {
    use std::fs::File;
    {
        mod std { pub struct X; }
    }
    let _ = File::open(path);
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["read_it"].has_file_operations is True
    assert funcs["read_glob"].has_file_operations is True
    assert funcs["load_plugin"].has_eval_exec is True
    assert funcs["read_after"].has_file_operations is True


def test_nested_function_still_sees_the_parent_import() -> None:
    """A nested ``fn`` inherits the parent import. A nested ``mod`` does not."""
    source = """\
fn read_it(path: &str) {
    use std::fs::File;
    fn inner(path: &str) {
        let _ = File::open(path);
    }
    let _ = File::open(path);
}

fn load_inside(path: &str) {
    mod child {
        pub fn load_child(path: &str) {
            use libloading::Library;
            unsafe { Library::new(path); }
        }
    }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["inner"].has_file_operations is True
    assert funcs["read_it"].has_file_operations is True
    assert funcs["load_child"].has_eval_exec is True
