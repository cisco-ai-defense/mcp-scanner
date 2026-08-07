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

PUNKPEYE_FASTMCP_ADDTOOL = """\
import { FastMCP } from "fastmcp";
import { z } from "zod";

const server = new FastMCP({ name: "demo", version: "1.0.0" });

async function addNumbers(args: { a: number; b: number }) {
  return String(args.a + args.b);
}

server.addTool({
  name: "add",
  description: "Add two numbers",
  parameters: z.object({ a: z.number(), b: z.number() }),
  execute: addNumbers,
});

server.addTool({
  name: "multiply",
  description: "Multiply two numbers",
  parameters: z.object({ a: z.number(), b: z.number() }),
  execute: async (args) => String(args.a * args.b),
});
"""

MCP_FRAMEWORK_MCPTOOL = """\
import { MCPTool } from "mcp-framework";
import { z } from "zod";

const AddSchema = z.object({
  a: z.number(),
  b: z.number(),
});

class AddTool extends MCPTool {
  name = "add";
  description = "Add two numbers";
  schema = AddSchema;

  async execute(input: { a: number; b: number }) {
    return String(input.a + input.b);
  }
}

class GreetTool extends MCPTool<typeof AddSchema> {
  name = "greet";
  description = "Greet someone";

  async execute(input: { a: number; b: number }) {
    return `hello ${input.a}`;
  }
}

export default AddTool;
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

FASTAPI_MCP_APP = """\
from fastapi import FastAPI
from fastapi_mcp import FastApiMCP

app = FastAPI()

@app.get("/items", operation_id="list_items")
def list_items():
    return []

@app.post("/items", operation_id="create_item")
async def create_item():
    return {}

mcp = FastApiMCP(app)
mcp.mount_http()
"""

FASTMCP_DECORATOR = """\
from fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool
def add(a: int, b: int) -> int:
    return a + b
"""

MCPSERVER_V2 = """\
from mcp.server.mcpserver import MCPServer

app = MCPServer("demo")

@app.tool
def greet(name: str) -> str:
    return f"hello {name}"
"""

PAGERDUTY_REGISTRATION = """\
from mcp.server.fastmcp import FastMCP

def add_read_only_tool(mcp_instance: FastMCP, tool):
    mcp_instance.add_tool(tool)

def list_incidents():
    return []

mcp = FastMCP("demo")
add_read_only_tool(mcp, list_incidents)
"""

FASTAPI_MCP_ROUTER = """\
from fastapi import APIRouter
from fastapi_mcp import FastApiMCP

router = APIRouter()

@router.get("/health", operation_id="health_check")
def health():
    return {"ok": True}

mcp = FastApiMCP(router)
"""

OFFICIAL_SDK_FASTMCP = """\
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool
def ping() -> str:
    return "pong"
"""

PROGRAMMATIC_ADD_TOOL = """\
from fastmcp import FastMCP

def multiply(a: int, b: int) -> int:
    return a * b

mcp = FastMCP("demo")
mcp.add_tool(multiply)
"""

VANILLA_FASTAPI_MCP_MOUNT = """\
from contextlib import asynccontextmanager

from fastapi import FastAPI
from mcp.server import MCPServer

mcp = MCPServer("Notes")


@mcp.tool()
def add_note(text: str) -> str:
    return f"Saved: {text}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(lifespan=lifespan)
app.mount("/mcp-server", mcp.streamable_http_app())


@app.get("/health")
def health():
    return {"status": "ok"}
"""

VANILLA_FASTAPI_REST_ONLY = """\
from fastapi import FastAPI

app = FastAPI()


@app.get("/items")
def list_items():
    return []


@app.post("/items")
def create_item():
    return {}
"""

FLASK_MCP_SERVER = """\
from flask import Flask
from flask_mcp_server import Mcp, mount_mcp

app = Flask(__name__)


@Mcp.tool(name="sum")
def sum_numbers(a: int, b: int) -> int:
    return a + b


@app.route("/health")
def health():
    return {"status": "ok"}


mount_mcp(app, url_prefix="/mcp")
"""

FLASK_REST_ONLY = """\
from flask import Flask

app = Flask(__name__)


@app.route("/items")
def list_items():
    return []


def helper():
    return None
"""

PLAIN_FLASK_HAND_ROLLED_MCP = """\
from flask import Flask, jsonify, request

app = Flask(__name__)


def add_numbers(a: int, b: int) -> int:
    return a + b


def search_items(query: str):
    return []


TOOLS = {
    "add": add_numbers,
    "search": search_items,
}


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    data = request.get_json(force=True)
    method = data.get("method")
    if method == "tools/list":
        return jsonify({"jsonrpc": "2.0", "result": {"tools": []}, "id": data.get("id")})
    if method == "tools/call":
        name = data.get("params", {}).get("name")
        handler = TOOLS[name]
        return jsonify({"jsonrpc": "2.0", "result": handler(**{}), "id": data.get("id")})
    return jsonify({"jsonrpc": "2.0", "error": {"code": -32601}, "id": data.get("id")})
"""

PLAIN_FLASK_MCP_HELPER_MODULE = """\
TOOLS = {
    "add": add_numbers,
}


def add_numbers(a: int, b: int) -> int:
    return a + b


def handle_request(method, params):
    if method == "tools/call":
        name = params.get("name")
        return TOOLS[name](**params.get("arguments", {}))
    if method == "tools/list":
        return {"tools": [{"name": n} for n in TOOLS]}
    return {}
"""

PLAIN_FLASK_HAND_ROLLED_REGISTER = """\
from flask import Flask, jsonify, request

app = Flask(__name__)
tool_registry = {}


def register_tool(name, handler):
    tool_registry[name] = handler


def multiply(a: int, b: int) -> int:
    return a * b


register_tool("multiply", multiply)


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    data = request.get_json(force=True)
    if data.get("method") == "tools/call":
        name = data["params"]["name"]
        return jsonify({"result": tool_registry[name]()})
    return jsonify({})
"""

PLAIN_FASTAPI_HAND_ROLLED_MCP = """\
from fastapi import FastAPI, Request

app = FastAPI()


async def add_numbers(a: int, b: int) -> int:
    return a + b


async def list_items():
    return []


TOOLS = {
    "add": add_numbers,
    "list_items": list_items,
}


@app.post("/mcp")
async def mcp_endpoint(request: Request):
    body = await request.json()
    method = body.get("method")
    if method == "tools/list":
        return {"jsonrpc": "2.0", "result": {"tools": []}, "id": body.get("id")}
    if method == "tools/call":
        name = body.get("params", {}).get("name")
        handler = TOOLS[name]
        result = await handler(**body.get("params", {}).get("arguments", {}))
        return {"jsonrpc": "2.0", "result": result, "id": body.get("id")}
    return {"jsonrpc": "2.0", "error": {"code": -32601}, "id": body.get("id")}


@app.get("/health")
async def health():
    return {"ok": True}
"""

PLAIN_FASTAPI_HAND_ROLLED_ROUTER = """\
from fastapi import APIRouter, Request

router = APIRouter()


def echo(message: str) -> str:
    return message


tool_handlers = {
    "echo": echo,
}


@router.post("/mcp")
async def mcp_endpoint(request: Request):
    body = await request.json()
    match body.get("method"):
        case "tools/list":
            return {"tools": []}
        case "tools/call":
            name = body["params"]["name"]
            return tool_handlers[name](**body["params"].get("arguments", {}))
    return {}
"""

PLAIN_FASTAPI_HAND_ROLLED_DISPATCH_TABLE = """\
from fastapi import FastAPI, Request

app = FastAPI()


def multiply(a: int, b: int) -> int:
    return a * b


MCP_METHODS = {
    "tools/list": lambda params: {"tools": [{"name": "multiply"}]},
    "tools/call": lambda params: multiply(**params.get("arguments", {})),
}


@app.post("/mcp")
async def mcp_rpc(request: Request):
    body = await request.json()
    handler = MCP_METHODS.get(body.get("method"))
    if handler is None:
        return {"error": {"code": -32601}}
    return {"result": handler(body.get("params", {}))}
"""

FASTMCP_HTTP_APP_MOUNT = """\
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool
def greet(name: str) -> str:
    return f"hello {name}"


mcp_app = mcp.http_app(path="/mcp")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp_app.lifespan(app):
        yield


app = FastAPI(lifespan=lifespan)
app.mount("/mcp-server", mcp_app)


@app.get("/health")
def health():
    return {"ok": True}
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


def test_punkpeye_fastmcp_addtool_object_literal() -> None:
    """punkpeye/fastmcp: server.addTool({ name, execute: fn })."""
    analyzer = NativeAnalyzer(PUNKPEYE_FASTMCP_ADDTOOL, "server.ts")
    assert analyzer._has_mcp_markers()
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"add", "multiply"}, names
    assert all(any("registration" in t for t in c.decorator_types) for c in caps)


def test_mcp_framework_mcptool_class_execute() -> None:
    """QuantGeekDev/mcp-framework: class extends MCPTool with execute()."""
    analyzer = NativeAnalyzer(MCP_FRAMEWORK_MCPTOOL, "AddTool.ts")
    assert analyzer._has_mcp_markers()
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"add", "greet"}, names
    assert all(
        any("mcp_framework.class" in t for t in c.decorator_types) for c in caps
    )


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


def test_fastapi_mcp_extracts_route_handlers() -> None:
    analyzer = NativeAnalyzer(FASTAPI_MCP_APP, "main.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"list_items", "create_item"}, names
    assert all(
        any("fastapi_mcp" in t for t in c.decorator_types) for c in caps
    )


def test_fastmcp_decorator_tool() -> None:
    analyzer = NativeAnalyzer(FASTMCP_DECORATOR, "server.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "add"


def test_mcpserver_v2_decorator_tool() -> None:
    analyzer = NativeAnalyzer(MCPSERVER_V2, "server.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "greet"


def test_add_read_only_tool_wrapper_registers_handler() -> None:
    analyzer = NativeAnalyzer(PAGERDUTY_REGISTRATION, "server.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "list_incidents"
    assert "<registration>.tool" in caps[0].decorator_types


def test_fastapi_mcp_extracts_apirouter_routes() -> None:
    analyzer = NativeAnalyzer(FASTAPI_MCP_ROUTER, "routes.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "health_check"


def test_official_sdk_fastmcp_import_path() -> None:
    analyzer = NativeAnalyzer(OFFICIAL_SDK_FASTMCP, "server.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "ping"


def test_programmatic_add_tool() -> None:
    analyzer = NativeAnalyzer(PROGRAMMATIC_ADD_TOOL, "server.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "multiply"
    assert "<registration>.tool" in caps[0].decorator_types


def test_vanilla_fastapi_mcp_mount_extracts_decorated_tools_only() -> None:
    analyzer = NativeAnalyzer(VANILLA_FASTAPI_MCP_MOUNT, "main.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"add_note"}, names
    assert any("web_transport" in t for c in caps for t in c.decorator_types)


def test_vanilla_fastapi_rest_routes_are_not_mcp_tools() -> None:
    analyzer = NativeAnalyzer(VANILLA_FASTAPI_REST_ONLY, "main.py")
    assert not analyzer._has_mcp_markers()
    caps = analyzer.extract_mcp_capability_contexts()
    assert caps == []


def test_flask_mcp_server_extracts_mcp_tool_not_rest_routes() -> None:
    analyzer = NativeAnalyzer(FLASK_MCP_SERVER, "app.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"sum_numbers"}, names
    assert "health" not in names


def test_flask_rest_only_has_no_capabilities() -> None:
    analyzer = NativeAnalyzer(FLASK_REST_ONLY, "app.py")
    assert not analyzer._has_mcp_markers()
    caps = analyzer.extract_mcp_capability_contexts()
    assert caps == []


def test_fastmcp_http_app_mount_on_fastapi() -> None:
    analyzer = NativeAnalyzer(FASTMCP_HTTP_APP_MOUNT, "main.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"greet"}, names
    assert "health" not in names


def test_plain_flask_hand_rolled_mcp_registry() -> None:
    analyzer = NativeAnalyzer(PLAIN_FLASK_HAND_ROLLED_MCP, "app.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"add", "search"}, names
    assert "mcp_endpoint" not in names
    assert all(
        any("hand_rolled_mcp" in t for t in c.decorator_types) for c in caps
    )


def test_plain_flask_hand_rolled_mcp_registry_annassign() -> None:
    """Annotated registry assignments (TOOLS: dict[str, Fn] = {...})."""
    source = """\
from typing import Callable

def add_numbers(a: int, b: int) -> int:
    return a + b

TOOLS: dict[str, Callable[..., int]] = {
    "add": add_numbers,
}

def handle_request(method, params):
    if method == "tools/call":
        return TOOLS[params["name"]](**params.get("arguments", {}))
    if method == "tools/list":
        return {"tools": []}
    return {}
"""
    analyzer = NativeAnalyzer(source, "mcp_helper.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "add"
    assert any("hand_rolled_mcp" in t for t in caps[0].decorator_types)


def test_plain_flask_mcp_helper_module_registry() -> None:
    analyzer = NativeAnalyzer(PLAIN_FLASK_MCP_HELPER_MODULE, "mcp_helper.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "add"


def test_plain_flask_hand_rolled_register_tool_call() -> None:
    analyzer = NativeAnalyzer(PLAIN_FLASK_HAND_ROLLED_REGISTER, "app.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "multiply"
    assert "mcp_endpoint" not in {c.name for c in caps}


def test_plain_fastapi_hand_rolled_mcp_registry() -> None:
    analyzer = NativeAnalyzer(PLAIN_FASTAPI_HAND_ROLLED_MCP, "main.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == {"add", "list_items"}, names
    assert "mcp_endpoint" not in names
    assert "health" not in names
    assert all(
        any("hand_rolled_mcp" in t for t in c.decorator_types) for c in caps
    )


def test_plain_fastapi_hand_rolled_apirouter_match_dispatch() -> None:
    analyzer = NativeAnalyzer(PLAIN_FASTAPI_HAND_ROLLED_ROUTER, "routes.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].name == "echo"
    assert "mcp_endpoint" not in {c.name for c in caps}


def test_plain_fastapi_hand_rolled_dispatch_table_does_not_extract_lambdas() -> None:
    """Dispatch tables that wrap handlers in lambdas stay conservative (no FP)."""
    analyzer = NativeAnalyzer(PLAIN_FASTAPI_HAND_ROLLED_DISPATCH_TABLE, "main.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert caps == []
