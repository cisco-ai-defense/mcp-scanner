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

"""Tests for dynamic / indirect MCP registration patterns (Gap 8).

Covers:
* Programmatic ``mcp.add_tool(fn)`` (Python).
* Decorator-factory applied to a bound method:
  ``mcp.tool(name="x")(self.method)`` (Python; the AWS-Labs pattern).
* Decorator-factory applied to a cross-file module attribute:
  ``mcp.tool()(docs.search_agentcore_docs)`` — emits an unresolved
  handler stub for the cross-file reference.
* Custom decorator wrappers like ``@safe_tool`` that delegate to
  ``mcp.tool()``.
* Loop / forEach registrations that emit unresolved-handler stubs.
* Factory-produced handlers (``server.tool('x', schema, make_handler())``)
  that emit unresolved-handler stubs.
"""

from mcpscanner.core.static_analysis import NativeAnalyzer


# ---------------------------------------------------------------------------
# Python: programmatic ``mcp.add_tool(fn)``.
# ---------------------------------------------------------------------------

PYTHON_PROGRAMMATIC = '''
from fastmcp import FastMCP

mcp = FastMCP("demo")

def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b

def sub(a: float, b: float) -> float:
    """Subtract."""
    return a - b

mcp.add_tool(add)
mcp.add_tool(sub)
'''


def test_python_programmatic_add_tool_classifies_handlers() -> None:
    """``mcp.add_tool(fn)`` must surface ``fn`` as an MCP tool (Gap 8)."""
    analyzer = NativeAnalyzer(PYTHON_PROGRAMMATIC, "programmatic.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert "add" in names, names
    assert "sub" in names, names


# ---------------------------------------------------------------------------
# Python: custom decorator wrapper.
# ---------------------------------------------------------------------------

PYTHON_WRAPPER_DECORATOR = '''
from fastmcp import FastMCP

mcp = FastMCP("demo")

def safe_tool(fn):
    """Custom wrapper that ultimately registers as a tool."""
    return mcp.tool()(fn)

@safe_tool
def add(a: float, b: float) -> float:
    """Add two numbers safely."""
    return a + b
'''


def test_python_wrapper_decorator_classifies_target() -> None:
    """A custom wrapper that returns ``mcp.tool()(fn)`` must classify
    its target as a tool (Gap 8)."""
    analyzer = NativeAnalyzer(PYTHON_WRAPPER_DECORATOR, "wrapper.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert "add" in names, names


# ---------------------------------------------------------------------------
# Python: decorator-factory applied to a bound method (AWS-Labs pattern).
# ---------------------------------------------------------------------------

PYTHON_BOUND_METHOD_REGISTRATION = '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


class ControlPlaneTools:
    def memory_create(self, name: str) -> dict:
        """Create a memory resource."""
        return {"name": name}

    def memory_get(self, name: str) -> dict:
        """Fetch a memory resource."""
        return {"name": name}

    def register(self, mcp):
        mcp.tool(name="memory_create")(self.memory_create)
        mcp.tool(name="memory_get")(self.memory_get)


class _NotAToolGroup:
    def helper(self):
        # Helpers in unrelated classes must NOT surface as capabilities.
        return 0
'''


def test_python_bound_method_decorator_factory_classifies_methods() -> None:
    """``mcp.tool(name='x')(self.method)`` inside a tool-group class
    must classify the target method as an MCP tool (Gap 8 extension).

    This is the registration pattern used by AWS-Labs MCP servers
    (e.g. amazon-bedrock-agentcore-mcp-server) that previously fell
    through the cracks.
    """
    analyzer = NativeAnalyzer(
        PYTHON_BOUND_METHOD_REGISTRATION, "controlplane.py"
    )
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert "memory_create" in names, names
    assert "memory_get" in names, names
    # Helpers in unrelated classes must not be picked up.
    assert "helper" not in names, names
    # Each registered method gets a ``<registration>.tool`` tag so
    # consumers can distinguish call-site registrations from decorator-
    # native ones.
    for cap in caps:
        if cap.name in {"memory_create", "memory_get"}:
            assert any(
                t == "<registration>.tool" for t in cap.decorator_types
            ), cap.decorator_types


# ---------------------------------------------------------------------------
# Python: decorator-factory applied to a cross-file module attribute.
# ---------------------------------------------------------------------------

PYTHON_CROSSFILE_DOCS_REGISTRATION = '''
from mcp.server.fastmcp import FastMCP
from .tools import docs

mcp = FastMCP("demo")

mcp.tool()(docs.search_agentcore_docs)
mcp.tool()(docs.fetch_agentcore_doc)
'''


PYTHON_MIXED_DECORATOR_AND_PROGRAMMATIC = '''
from fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b

def sub(a: float, b: float) -> float:
    """Subtract."""
    return a - b

mcp.add_tool(sub)
'''


def test_python_programmatic_not_shadowed_by_decorator_tools() -> None:
    """Gap 8 must run even when ``@mcp.tool()`` tools exist in the file."""
    analyzer = NativeAnalyzer(
        PYTHON_MIXED_DECORATOR_AND_PROGRAMMATIC, "mixed.py"
    )
    names = {c.name for c in analyzer.extract_mcp_capability_contexts()}
    assert names == {"add", "sub"}, names


PYTHON_SELF_MCP_NESTED = '''
from fastmcp import FastMCP

class Server:
    def __init__(self):
        self.mcp = FastMCP("demo")

    def setup(self):
        @self.mcp.tool()
        def add(a: float, b: float) -> float:
            """Add numbers."""
            return a + b
'''


def test_python_self_mcp_nested_decorator() -> None:
    """``@self.mcp.tool()`` inside a method must be recognized."""
    from mcpscanner.core.static_analysis.context_extractor import ContextExtractor

    names = {
        c.name
        for c in ContextExtractor(PYTHON_SELF_MCP_NESTED, "nested.py")
        .extract_mcp_function_contexts()
    }
    assert "add" in names, names


TS_MEMBER_HANDLER = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "demo", version: "1.0" });
const obj = { handler: (a, b) => a + b };
server.tool("add", {}, obj.handler);
"""


def test_ts_member_expression_handler_emits_capability() -> None:
    """``server.tool('add', schema, obj.handler)`` must not be dropped."""
    analyzer = NativeAnalyzer(TS_MEMBER_HANDLER, "member.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert any(c.name == "add" for c in caps), [c.name for c in caps]


TS_DYNAMIC_NAME = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "demo", version: "1.0" });
const toolName = "add";
function handler(a, b) { return a + b; }
server.tool(toolName, {}, handler);
"""


def test_ts_dynamic_tool_name_emits_unresolved_stub() -> None:
    """``server.tool(toolName, schema, handler)`` must emit a capability."""
    analyzer = NativeAnalyzer(TS_DYNAMIC_NAME, "dynamic.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert caps, names
    assert any(
        "toolName" in n or "handler" in n for n in names
    ), names


def test_python_crossfile_module_attr_emits_unresolved_stub() -> None:
    """``mcp.tool()(docs.search_agentcore_docs)`` references a handler
    defined in another module. Emit unresolved stubs so the
    registration is at least visible downstream (Gap 8 extension)."""
    analyzer = NativeAnalyzer(
        PYTHON_CROSSFILE_DOCS_REGISTRATION, "server.py"
    )
    caps = analyzer.extract_mcp_capability_contexts()
    labels = {c.name for c in caps}
    assert "docs.search_agentcore_docs" in labels, labels
    assert "docs.fetch_agentcore_doc" in labels, labels
    for cap in caps:
        assert any(
            t == "<registration.unresolved>.tool"
            for t in cap.decorator_types
        ), cap.decorator_types


# ---------------------------------------------------------------------------
# JS/TS: Graph-style endpoint loops (``tool.alias`` + static endpoint table).
# ---------------------------------------------------------------------------

GRAPH_ENDPOINT_LOOP = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "graph", version: "1.0" });

const api = {
  endpoints: [
    { alias: "list-messages", description: "List messages", schema: {} },
    { alias: "get-user", description: "Get user", schema: {} },
    { alias: "list-onenote-notebooks", description: "OneNote", schema: {} },
  ],
};

for (const tool of api.endpoints) {
  const toolDescription = tool.description;
  const paramSchema = tool.schema;
  server.tool(
    tool.alias,
    toolDescription,
    paramSchema,
    {},
    async (params) => ({ content: [{ type: "text", text: "ok" }] }),
  );
}
"""


def test_graph_endpoint_loop_expands_literal_aliases() -> None:
    """``for (const tool of api.endpoints)`` + ``tool.alias`` must expand
    every static ``alias`` in the endpoint table."""
    analyzer = NativeAnalyzer(GRAPH_ENDPOINT_LOOP, "graph-tools.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert "list-messages" in names, names
    assert "get-user" in names, names
    assert "list-onenote-notebooks" in names, names
    table_caps = [
        c
        for c in caps
        if any("registration.table" in t for t in c.decorator_types)
    ]
    assert len(table_caps) >= 3, [c.decorator_types for c in caps]


def test_graph_loop_inline_handler_uses_alias_not_description() -> None:
    """The shared inline handler registration must prefer ``tool.alias``."""
    analyzer = NativeAnalyzer(GRAPH_ENDPOINT_LOOP, "graph-tools.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    reg_caps = [
        c for c in caps if any(t == "<registration>.tool" for t in c.decorator_types)
    ]
    assert reg_caps, [c.decorator_types for c in caps]
    assert any("tool.alias" in c.name for c in reg_caps), [c.name for c in reg_caps]
    assert not any(c.name == "toolDescription" for c in reg_caps), [
        c.name for c in reg_caps
    ]


# ---------------------------------------------------------------------------
# JS/TS: loop registration → unresolved stubs.
# ---------------------------------------------------------------------------

JS_LOOP_REGISTRATION = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });

const tools = [
  { name: "add", schema: {}, fn: (a, b) => a + b },
  { name: "sub", schema: {}, fn: (a, b) => a - b },
];

tools.forEach((m) => {
  server.tool(m.name, m.schema, m.fn);
});
"""


def test_js_loop_registration_emits_unresolved_or_inline_handlers() -> None:
    """``tools.forEach(m => server.tool(m.name, m.schema, m.fn))`` is dynamic.

    Static names from the ``tools`` table are not promoted to capabilities
    unless that array is reached through an explicit ``for...of`` iteration.
    """
    analyzer = NativeAnalyzer(JS_LOOP_REGISTRATION, "loop.js")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"m.name"}, names
    assert any(
        any("registration.unresolved" in t for t in c.decorator_types) for c in caps
    ), [c.decorator_types for c in caps]
