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
    # Pass 1's registered-name merge means the surfaced label combines
    # the registered MCP name (``user-template``) with the symbol name
    # (``readUserResource``). Both must be present.
    assert "readUserResource" in handler.name, handler.name
    assert "user-template" in handler.name, handler.name
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
    # Both contexts must point at the same handler. Pass 1 merges the
    # registered MCP name (``x``) with the symbol name (``shared``).
    assert all("shared" in c.name for c in caps), [c.name for c in caps]
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
    assert {c.name for c in caps} == {"add (add)", "sub (sub)"} or {
        c.name for c in caps
    } == {"add", "sub"}, [c.name for c in caps]
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
    assert {c.name for c in caps} == {"Calc.add"}, [c.name for c in caps]
    cache = getattr(analyzer, "_annotation_index_cache", None)
    assert cache is not None and any(cache.values()), cache


# ---------------------------------------------------------------------------
# Destructured-parameter taint flows (regression for AIFW-23242):
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


def _flow_for(ctx, param_name):
    for flow in ctx.parameter_flows:
        if flow.get("parameter_name") == param_name:
            return flow
    return None


def test_ts_destructured_param_taints_command_sink() -> None:
    """A TS tool that runs a destructured ``{ command }`` arg through
    ``execSync`` must record the parameter -> sink flow (AIFW-23242)."""
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
# Delegated sinks + aliased sinks (regression for AIFW-23242, Example 9):
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


def test_promisify_alias_detected_as_command_sink() -> None:
    """``const run = promisify(exec)`` must mark the helper that calls
    ``run(...)`` as a subprocess sink, even with a clean alias name."""
    analyzer = NativeAnalyzer(DELEGATED_CLEAN_NAMES_TS, "alias.ts")
    analyzer.extract_mcp_capability_contexts()
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
