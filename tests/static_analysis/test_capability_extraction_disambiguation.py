"""Disambiguation / precision tests for capability extraction.

Covers four concerns where the extractor previously made a coarse
decision that could silently misattribute a capability:

1. Import-map disambiguation in ``_resolve_cross_file_handler``: when
   two files in the call graph define a function with the same name,
   prefer the one named in the calling file's imports.
2. Python decorator receiver verification: ``@<receiver>.tool`` only
   classifies as MCP when ``<receiver>`` is bound to an MCP SDK
   instance; unrelated DSLs (``toolbar.tool(...)``) no longer
   false-positive.
3. Annotation regex captures the leaf identifier across ``::``,
   ``.``, and ``\\`` namespace separators (e.g.
   ``@org.springframework.ai.Tool`` → ``Tool``).
4. Python programmatic registrations resolve cross-file handler
   references via the call graph (e.g. ``mcp.tool()(docs.search_x)``
   with ``docs`` imported from another module).
"""

from pathlib import Path

import pytest

from mcpscanner.core.static_analysis import NativeAnalyzer
from mcpscanner.core.static_analysis.interprocedural.call_graph_analyzer import (
    CallGraphAnalyzer,
)
from mcpscanner.core.static_analysis.interprocedural.treesitter_call_graph import (
    TreeSitterCallGraphAnalyzer,
)
from mcpscanner.core.static_analysis.native_analyzer import _MCP_ANNOTATION_RE


# ---------------------------------------------------------------------------
# Annotation regex covers ``::``, ``.``, ``\\`` namespace separators.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "annotation, expected_leaf",
    [
        ("@Tool", "Tool"),
        ("@McpTool", "McpTool"),
        ("@org.springframework.ai.Tool", "Tool"),
        ("[McpServerTool]", "McpServerTool"),
        ("[ModelContextProtocol.Server.McpServerTool]", "McpServerTool"),
        ("#[tool]", "tool"),
        ("#[mcp::tool]", "tool"),
        (r"#[App\Mcp\Tool]", "Tool"),
        ("# @tool", "tool"),
    ],
)
def test_annotation_regex_captures_leaf_identifier(annotation, expected_leaf):
    """The compiled regex must surface the trailing identifier no matter
    which namespace separator the language uses."""
    m = _MCP_ANNOTATION_RE.search(annotation)
    assert m is not None, annotation
    assert m.group(1) == expected_leaf


def test_spring_ai_fully_qualified_tool_classifies_as_mcp():
    """Regression: ``@org.springframework.ai.Tool`` must classify as
    an MCP tool now that the regex walks ``.`` separators."""
    src = """\
package com.example;
import org.springframework.ai.Tool;

public class Calc {
    @org.springframework.ai.Tool
    public int add(int a, int b) { return a + b; }
}
"""
    analyzer = NativeAnalyzer(src, "Calc.java")
    caps = analyzer.extract_mcp_capability_contexts()
    assert any(c.name.endswith("add") for c in caps), [c.name for c in caps]


# ---------------------------------------------------------------------------
# Import-map disambiguation for cross-file handler resolution.
# ---------------------------------------------------------------------------

INDEX_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { addHandler } from "./tools/add";

const server = new McpServer({ name: "demo", version: "1.0" });
server.registerTool("add", { description: "Add two numbers" }, addHandler);
"""

ADD_TS = """\
export async function addHandler(input: { a: number; b: number }) {
  return input.a + input.b;
}
"""

# Same name, different file — this is the "wrong-file wins" failure
# the import-map disambiguator is meant to fix.
DECOY_TS = """\
export function addHandler(input: any) {
  // Unrelated implementation that happens to share the symbol name.
  throw new Error("decoy");
}
"""


def test_import_map_disambiguates_same_named_handler(tmp_path: Path) -> None:
    """When two files define ``addHandler``, the cross-file resolver
    prefers the file named in the calling file's import statement."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "fixtures").mkdir()

    index_path = tmp_path / "index.ts"
    add_path = tmp_path / "tools" / "add.ts"
    decoy_path = tmp_path / "fixtures" / "add.ts"
    index_path.write_text(INDEX_TS)
    add_path.write_text(ADD_TS)
    decoy_path.write_text(DECOY_TS)

    cga = TreeSitterCallGraphAnalyzer("typescript")
    # Ingest the decoy FIRST so that without the fix it would win the
    # legacy "first suffix match" race.
    cga.add_file(decoy_path, DECOY_TS)
    cga.add_file(add_path, ADD_TS)
    cga.add_file(index_path, INDEX_TS)
    cga.build_call_graph()

    analyzer = NativeAnalyzer(INDEX_TS, str(index_path))
    caps = analyzer.extract_mcp_capability_contexts(cross_file_analyzer=cga)

    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    # The cross-file stub records the defining path. With the import
    # map fix it must be ``tools/add.ts``, not ``fixtures/add.ts``.
    source = getattr(cap, "source_file", "") or ""
    assert source.endswith("tools/add.ts"), source


def test_import_map_falls_back_to_suffix_when_no_import_match(
    tmp_path: Path,
) -> None:
    """If the calling file does not import the handler at all, the
    resolver still falls back to the legacy suffix search so behavior
    stays usable."""
    src = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });
server.registerTool("add", { description: "x" }, addHandler);
"""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "add.ts").write_text(ADD_TS)

    cga = TreeSitterCallGraphAnalyzer("typescript")
    cga.add_file(tmp_path / "tools" / "add.ts", ADD_TS)
    cga.build_call_graph()

    analyzer = NativeAnalyzer(src, str(tmp_path / "no_import.ts"))
    caps = analyzer.extract_mcp_capability_contexts(cross_file_analyzer=cga)
    # Without an import line the resolver still surfaces the handler
    # (legacy behavior) — but only because there's exactly one file
    # in the graph defining the symbol.
    assert len(caps) == 1
    tags = caps[0].decorator_types
    assert any("registration.cross_file" in t for t in tags), tags


# ---------------------------------------------------------------------------
# Python decorator receiver verification.
# ---------------------------------------------------------------------------

def test_python_decorator_rejected_when_receiver_is_unrelated_dsl():
    """``@toolbar.tool(...)`` on an unrelated DSL must NOT classify
    as an MCP tool when an MCP server instance is also bound in the
    file (loose-mode shouldn't hide unrelated decorators)."""
    src = """\
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

class Toolbar:
    def tool(self, *a, **kw):
        def deco(fn):
            return fn
        return deco

toolbar = Toolbar()

@toolbar.tool("save")
def save_state():
    \"\"\"Save state via toolbar.\"\"\"
    return None

@mcp.tool()
def real_tool(x: int) -> int:
    \"\"\"A real MCP tool.\"\"\"
    return x + 1
"""
    analyzer = NativeAnalyzer(src, "server.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = [c.name for c in caps]
    assert "real_tool" in names, names
    assert "save_state" not in names, names


def test_python_decorator_loose_mode_when_no_mcp_instance():
    """When no MCP server instance is found in the file (e.g., the
    instance lives in another module) the verifier degrades into
    ``loose mode`` and accepts any ``@<x>.tool`` so the legacy
    detection still works."""
    src = """\
@mcp.tool()
def loose_tool(x: int) -> int:
    \"\"\"Tool with imported MCP instance not visible here.\"\"\"
    return x + 1
"""
    analyzer = NativeAnalyzer(src, "server.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = [c.name for c in caps]
    assert "loose_tool" in names, names


# ---------------------------------------------------------------------------
# Python programmatic registration uses the cross-file call graph.
# ---------------------------------------------------------------------------

PY_SERVER = """\
from mcp.server.fastmcp import FastMCP
from .tools import docs

mcp = FastMCP("demo")
mcp.tool()(docs.search_agentcore_docs)
"""

PY_DOCS = """\
def search_agentcore_docs(query: str) -> str:
    \"\"\"Search the Bedrock AgentCore docs.\"\"\"
    return "..."
"""


def test_python_programmatic_registration_resolves_via_call_graph(
    tmp_path: Path,
) -> None:
    """``mcp.tool()(docs.search_agentcore_docs)`` with ``docs``
    imported from another module must surface as a cross-file stub —
    not the bare ``unresolved`` form — so the report layer points at
    the right file."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "__init__.py").write_text("")
    server_path = tmp_path / "server.py"
    docs_path = tmp_path / "tools" / "docs.py"
    server_path.write_text(PY_SERVER)
    docs_path.write_text(PY_DOCS)

    cga = CallGraphAnalyzer()
    cga.add_file(server_path, PY_SERVER)
    cga.add_file(docs_path, PY_DOCS)
    cga.build_call_graph()

    analyzer = NativeAnalyzer(PY_SERVER, str(server_path))
    caps = analyzer.extract_mcp_capability_contexts(cross_file_analyzer=cga)
    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    tags = cap.decorator_types
    assert any("registration.cross_file" in t for t in tags), tags
    source = getattr(cap, "source_file", "") or ""
    assert source.endswith("tools/docs.py"), source


# ---------------------------------------------------------------------------
# Relative-import round-trip in ``_py_extract_imports``.
# ---------------------------------------------------------------------------
#
# The cross-file resolver above relies on the calling file's import
# statements to bind a name like ``handlers`` to a module path. When
# ``ast.ImportFrom`` represents a relative import, ``node.module`` is
# ``None`` and the dot count lives in ``node.level``. If the dots are
# dropped during round-trip extraction, ``from . import handlers``
# becomes the unparseable ``"from  import handlers"`` and the
# downstream regex collector silently emits no entry — which means
# the cross-file resolver can never fire for the very common
# packaged-server shape. The two tests below pin both halves of the
# round-trip: the literal string and the resulting capability stub.

PY_REL_SERVER = """\
from mcp.server.fastmcp import FastMCP
from . import handlers

mcp = FastMCP("demo")
mcp.tool(name="upper")(handlers.do_thing)
"""

PY_REL_HANDLERS = """\
def do_thing(payload: str) -> str:
    return payload.upper()
"""


def test_relative_import_round_trips_with_leading_dots():
    """``from . import handlers`` and ``from ..pkg import x`` must
    survive round-trip through ``_py_extract_imports`` so the
    downstream regex collector can bind names to module paths."""
    import ast

    src = (
        "from . import handlers\n"
        "from ..pkg import sibling\n"
        "from .tools import docs\n"
        "from mcp.server.fastmcp import FastMCP\n"
    )
    tree = ast.parse(src)
    analyzer = NativeAnalyzer(src, "server.py")
    imports = analyzer._py_extract_imports(tree)
    # The leading-dot relative imports must keep their dots so the
    # downstream regex collector can parse them.
    assert "from . import handlers" in imports, imports
    assert "from ..pkg import sibling" in imports, imports
    assert "from .tools import docs" in imports, imports
    # Non-relative imports continue to round-trip unchanged.
    assert "from mcp.server.fastmcp import FastMCP" in imports, imports


def test_bare_from_dot_import_unblocks_cross_file_resolver(
    tmp_path: Path,
) -> None:
    """Pin the end-to-end behavior: a server using the bare
    ``from . import handlers`` form must emit a cross-file stub when
    the call graph contains the handler. Before the leading-dot fix
    in ``_py_extract_imports`` this test surfaced an ``unresolved``
    stub instead of a ``cross_file`` one."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    server_path = pkg / "server.py"
    handlers_path = pkg / "handlers.py"
    server_path.write_text(PY_REL_SERVER)
    handlers_path.write_text(PY_REL_HANDLERS)

    cga = CallGraphAnalyzer()
    cga.add_file(server_path, PY_REL_SERVER)
    cga.add_file(handlers_path, PY_REL_HANDLERS)
    cga.build_call_graph()

    analyzer = NativeAnalyzer(PY_REL_SERVER, str(server_path))
    caps = analyzer.extract_mcp_capability_contexts(cross_file_analyzer=cga)
    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    tags = cap.decorator_types
    assert any("registration.cross_file" in t for t in tags), tags
    source = getattr(cap, "source_file", "") or ""
    assert source.endswith("handlers.py"), source
