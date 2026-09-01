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

"""Third-party MCP server framework detection (mcp-framework, mcp-use, …)."""

import pytest

from mcpscanner.core.static_analysis import NativeAnalyzer

MCP_FRAMEWORK_SUBCLASS = """\
import { MCPTool, McpInput } from "mcp-framework";
import { z } from "zod";

const schema = { a: z.number(), b: z.number() };

class AddTool extends MCPTool {
  name = "add";
  description = "Add two numbers";
  schema = schema;

  async execute(input: McpInput<this>) {
    return input.a + input.b;
  }
}

function helper(x: number): number {
  return x;
}
"""

MCP_USE_SERVER_TOOL = """\
import { MCPServer, text } from "mcp-use";

const server = new MCPServer({ name: "demo", version: "1.0.0" });

function helper(v: number): number {
  return v;
}

server.tool(
  "add",
  { description: "Add two numbers" },
  async ({ a, b }: { a: number; b: number }) => text(String(helper(a) + b)),
);
"""

EASY_MCP_TOOL = """\
import EasyMCP from "easy-mcp";

const mcp = EasyMCP.create("demo", { version: "1.0.0" });

function helper(v: number): number {
  return v;
}

mcp.tool({
  name: "add",
  description: "Add two numbers",
  fn: (args: { a: number; b: number }) => helper(args.a) + args.b,
});
"""

EASY_MCP_DECORATOR = """\
import EasyMCP, { Tool } from "easy-mcp";

class DemoMCP extends EasyMCP {
  @Tool({ name: "add", description: "Add two numbers" })
  add(a: number, b: number) {
    return a + b;
  }
}
"""

XMCP_DEFAULT_EXPORT = """\
import { type InferSchema, type ToolMetadata } from "xmcp";
import { z } from "zod";

export const schema = {
  name: z.string(),
};

export const metadata: ToolMetadata = {
  name: "greet",
  description: "Greet the user",
};

export default function greet({ name }: InferSchema<typeof schema>) {
  return `Hello, ${name}!`;
}
"""

MCP_GOLANG_REGISTER = """\
package main

import (
    mcp_golang "github.com/metoro-io/mcp-golang"
)

type AddArgs struct {
    A float64 `json:"a" jsonschema:"required"`
    B float64 `json:"b" jsonschema:"required"`
}

func helper(x float64) float64 { return x }

func main() {
    server := mcp_golang.NewServer(mcp_golang.NewStdioServerTransport())
    server.RegisterTool("add", "Add two numbers", func(args AddArgs) (*mcp_golang.ToolResponse, error) {
        return mcp_golang.NewToolResponse(mcp_golang.NewTextContent("ok")), nil
    })
}
"""

FOXY_CONTEXTS_NEW_TOOL = """\
package main

import (
    "context"
    "github.com/strowk/foxy-contexts/pkg/fxctx"
    "github.com/strowk/foxy-contexts/pkg/mcp"
)

func helper() string { return "ok" }

func NewAddTool() fxctx.Tool {
    return fxctx.NewTool(
        &mcp.Tool{
            Name:        "add",
            Description: nil,
        },
        func(_ context.Context, _ map[string]interface{}) *mcp.CallToolResult {
            _ = helper()
            return nil
        },
    )
}
"""

QUARKUS_MCP_TOOL = """\
package demo;

import io.quarkiverse.mcp.server.Tool;
import io.quarkiverse.mcp.server.ToolArg;

public class Calc {
    private double helper(double x) { return x; }

    @Tool(description = "Add two numbers")
    double add(@ToolArg(description = "First") double a,
               @ToolArg(description = "Second") double b) {
        return helper(a) + helper(b);
    }
}
"""

RUST_MCP_TOOL_MACRO = """\
use pmcp_macros::mcp_tool;

fn helper(x: i32) -> i32 { x }

#[mcp_tool(description = "Add two numbers")]
async fn add(a: i32, b: i32) -> i32 {
    helper(a) + helper(b)
}
"""

FRAMEWORK_FIXTURES = [
    pytest.param(
        MCP_FRAMEWORK_SUBCLASS,
        "AddTool.ts",
        {"add"},
        id="mcp-framework-subclass",
    ),
    pytest.param(
        MCP_USE_SERVER_TOOL,
        "index.ts",
        {"add"},
        id="mcp-use-server-tool",
    ),
    pytest.param(
        EASY_MCP_TOOL,
        "server.ts",
        {"add"},
        id="easy-mcp-tool-config",
    ),
    pytest.param(
        EASY_MCP_DECORATOR,
        "server.ts",
        {"DemoMCP.add"},
        id="easy-mcp-decorator",
    ),
    pytest.param(
        XMCP_DEFAULT_EXPORT,
        "src/tools/greet.ts",
        {"greet"},
        id="xmcp-default-export",
    ),
    pytest.param(
        MCP_GOLANG_REGISTER,
        "main.go",
        {"add"},
        id="mcp-golang-register",
    ),
    pytest.param(
        FOXY_CONTEXTS_NEW_TOOL,
        "main.go",
        {"add"},
        id="foxy-contexts-newtool",
    ),
    pytest.param(
        QUARKUS_MCP_TOOL,
        "Calc.java",
        {"Calc.add"},
        id="quarkus-mcp-tool",
    ),
    pytest.param(
        RUST_MCP_TOOL_MACRO,
        "tools.rs",
        {"add"},
        id="pmcp-mcp-tool-macro",
    ),
]


@pytest.mark.parametrize("source,path,expected_names", FRAMEWORK_FIXTURES)
def test_framework_capability_extraction(
    source: str, path: str, expected_names: set[str]
) -> None:
    analyzer = NativeAnalyzer(source, path)
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    assert names == expected_names, (
        f"framework fixture {path!r}: expected {expected_names!r}, got {names!r}"
    )
