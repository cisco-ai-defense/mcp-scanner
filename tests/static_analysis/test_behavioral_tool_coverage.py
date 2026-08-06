"""Regression tests for real-world behavioral tool coverage gaps."""

from __future__ import annotations

from mcpscanner.core.analyzers.behavioral.code_analyzer import (
    BehavioralCodeAnalyzer,
    _AcceptedFile,
)
from mcpscanner.core.static_analysis.native_analyzer import NativeAnalyzer

GRAFANA_MUST_TOOL = """\
package tools

import (
    "context"
    mcpgrafana "github.com/grafana/mcp-grafana"
    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
)

func listDatasources(ctx context.Context, args ListDatasourcesParams) (*ListDatasourcesResult, error) {
    return nil, nil
}

var ListDatasources = mcpgrafana.MustTool(
    "list_datasources",
    "List datasources",
    listDatasources,
    mcp.WithReadOnlyHintAnnotation(true),
)

func AddDatasourceTools(mcp *server.MCPServer, enableWriteTools bool) {
    ListDatasources.Register(mcp)
}
"""

PLAYWRIGHT_DEFINE_TOOL = """\
import { defineTool, defineTabTool } from './tool';

const navigate = defineTool({
  capability: 'core-navigation',
  schema: {
    name: 'browser_navigate',
    title: 'Navigate',
    description: 'Navigate to a URL',
    inputSchema: {},
    type: 'action',
  },
  handle: async (context, params, response) => {
    await context.ensureTab();
  },
});

const goBack = defineTabTool({
  capability: 'core-navigation',
  schema: {
    name: 'browser_navigate_back',
    title: 'Go back',
    description: 'Go back',
    inputSchema: {},
    type: 'action',
  },
  handle: async (tab, params, response) => {
    await tab.page.goBack();
  },
});

export default [navigate, goBack];
"""

PAGERDUTY_TOOL_MODULE = """\
def list_incidents():
    \"\"\"List incidents.\"\"\"
    return []

def _internal_helper():
    return None
"""

GO_CLIENT_RESOURCE_FP = """\
package tools

type client struct{}

func (c *client) resource(ctx context.Context, path string) ([]byte, error) {
    return nil, nil
}
"""


def test_mark3labs_musttool_extracts_named_handler() -> None:
    analyzer = NativeAnalyzer(GRAFANA_MUST_TOOL, "datasources.go")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    assert caps[0].name.startswith("list_datasources"), caps[0].name
    call_names = {c.get("name") for c in caps[0].function_calls or []}
    assert "listDatasources" in call_names or caps[0].line_number > 0


def test_define_tool_extracts_schema_name_and_handle() -> None:
    analyzer = NativeAnalyzer(PLAYWRIGHT_DEFINE_TOOL, "navigate.ts")
    assert analyzer._has_mcp_markers()
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"browser_navigate", "browser_navigate_back"}, names
    assert all(c.line_number > 0 for c in caps)


def test_tool_handler_module_extracts_public_functions() -> None:
    analyzer = NativeAnalyzer(PAGERDUTY_TOOL_MODULE, "pagerduty_mcp/tools/incidents.py")
    assert not analyzer._has_mcp_markers()
    caps = analyzer.extract_mcp_capability_contexts(tool_handler_module=True)
    assert len(caps) == 1
    assert caps[0].name == "list_incidents"
    assert "<tool_module>.tool" in caps[0].decorator_types


def test_generic_client_resource_is_not_mcp_registration() -> None:
    analyzer = NativeAnalyzer(GO_CLIENT_RESOURCE_FP, "client.go")
    caps = analyzer.extract_mcp_capability_contexts()
    assert caps == []


def test_expand_tool_handler_modules_includes_sibling_tools_dir(tmp_path) -> None:
    pkg = tmp_path / "pagerduty_mcp"
    tools = pkg / "tools"
    tools.mkdir(parents=True)
    server_py = pkg / "server.py"
    server_py.write_text("from pagerduty_mcp.tools import read_tools\n", encoding="utf-8")
    (tools / "incidents.py").write_text("def list_incidents(): pass\n", encoding="utf-8")
    (tools / "alerts.py").write_text("def list_alerts(): pass\n", encoding="utf-8")

    analyzer = BehavioralCodeAnalyzer.__new__(BehavioralCodeAnalyzer)
    accepted = [
        _AcceptedFile(
            path=str(server_py),
            source_bytes=server_py.read_bytes(),
            source_text=server_py.read_text(encoding="utf-8"),
        )
    ]
    source_files = [
        str(server_py),
        str(tools / "incidents.py"),
        str(tools / "alerts.py"),
    ]
    expanded = analyzer._expand_tool_handler_modules(accepted, source_files)
    handler_paths = {item.path for item in expanded if item.tool_handler_module}
    assert str(tools / "incidents.py") in handler_paths
    assert str(tools / "alerts.py") in handler_paths
