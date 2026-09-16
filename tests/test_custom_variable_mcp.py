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

"""MCP capability detection when the server instance is not named ``mcp``.

Every other capability-extraction fixture in the suite writes
``mcp = FastMCP(...)`` and decorates with ``@mcp.tool()``. Real servers name
the instance whatever they like, and a scanner that only recognizes the
conventional name would silently analyze nothing on those servers. These
tests pin detection to the decorator shape rather than the variable name.
"""

import pytest

from mcpscanner.core.static_analysis import NativeAnalyzer

CUSTOM_VARIABLE_TOOL = '''
from mcp.server.fastmcp import FastMCP
hello_mcp = FastMCP("Bearer-Protected SSE Server")

@hello_mcp.tool()
def hello(name: str) -> str:
    """
    Simple tool that greets the provided name.
    """
    return f"Hello, {name}!"

@hello_mcp.tool()
def add(a: int, b: int) -> int:
    """
    Adds two numbers and returns the sum.
    """
    return a + b
'''

MY_SERVER_VARIABLE = '''
from mcp.server.fastmcp import FastMCP
my_server = FastMCP("My Custom Server")

@my_server.prompt()
def create_prompt(text: str) -> str:
    """
    Creates a prompt from text.
    """
    return f"Prompt: {text}"

@my_server.resource("resource://example")
def get_resource(id: str) -> dict:
    """
    Gets a resource by ID.
    """
    return {"id": id, "data": "example"}
'''

API_VARIABLE = '''
from mcp.server.fastmcp import FastMCP
api = FastMCP("API Server")

@api.tool()
def fetch_data(url: str) -> str:
    """
    Fetches data from a URL.
    """
    import requests
    return requests.get(url).text
'''

MIXED_DECORATORS = '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("Standard Server")
custom_mcp = FastMCP("Custom Server")

@mcp.tool()
def standard_tool(x: int) -> int:
    """Standard tool."""
    return x * 2

@custom_mcp.tool()
def custom_tool(y: str) -> str:
    """Custom tool."""
    return y.upper()

@custom_mcp.prompt()
def custom_prompt(text: str) -> str:
    """Custom prompt."""
    return f"Custom: {text}"
'''

STANDARD_VARIABLE = '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("Standard Server")

@mcp.tool()
def standard_function(x: int) -> int:
    """Standard function."""
    return x * 2
'''


def capabilities(source: str):
    """Extract capability contexts keyed by function name."""
    found = NativeAnalyzer(source, "test.py").extract_mcp_capability_contexts()
    return {ctx.name: ctx for ctx in found}


class TestCustomVariableMCPDetection:
    """Detection keys off the decorator, not the instance's variable name."""

    def test_detects_tools_on_custom_named_instance(self):
        caps = capabilities(CUSTOM_VARIABLE_TOOL)

        assert set(caps) == {"hello", "add"}
        assert "hello_mcp.tool" in caps["hello"].decorator_types
        assert "hello_mcp.tool" in caps["add"].decorator_types

    def test_detects_prompts_and_resources_on_custom_named_instance(self):
        caps = capabilities(MY_SERVER_VARIABLE)

        assert set(caps) == {"create_prompt", "get_resource"}
        assert "my_server.prompt" in caps["create_prompt"].decorator_types
        assert "my_server.resource" in caps["get_resource"].decorator_types

    def test_detects_short_instance_name(self):
        caps = capabilities(API_VARIABLE)

        assert set(caps) == {"fetch_data"}
        assert "api.tool" in caps["fetch_data"].decorator_types

    def test_two_instances_in_one_file_are_both_detected(self):
        caps = capabilities(MIXED_DECORATORS)

        assert set(caps) == {"standard_tool", "custom_tool", "custom_prompt"}
        assert "mcp.tool" in caps["standard_tool"].decorator_types
        assert "custom_mcp.tool" in caps["custom_tool"].decorator_types
        assert "custom_mcp.prompt" in caps["custom_prompt"].decorator_types

    def test_conventional_instance_name_still_detected(self):
        caps = capabilities(STANDARD_VARIABLE)

        assert set(caps) == {"standard_function"}
        assert "mcp.tool" in caps["standard_function"].decorator_types


class TestCustomVariableMetadataExtraction:
    """A custom instance name must not degrade the extracted metadata.

    The behavioral analyzer reasons over docstrings, parameters, and return
    types, so these carrying through matters as much as the tool being found
    at all.
    """

    def test_docstrings_survive(self):
        caps = capabilities(CUSTOM_VARIABLE_TOOL)

        assert "greets the provided name" in caps["hello"].docstring
        assert "Adds two numbers" in caps["add"].docstring

    def test_parameters_survive(self):
        caps = capabilities(CUSTOM_VARIABLE_TOOL)

        assert [p["name"] for p in caps["hello"].parameters] == ["name"]
        assert caps["hello"].parameters[0]["type"] == "str"
        assert [p["name"] for p in caps["add"].parameters] == ["a", "b"]

    def test_return_types_survive(self):
        caps = capabilities(CUSTOM_VARIABLE_TOOL)

        assert caps["hello"].return_type == "str"
        assert caps["add"].return_type == "int"


@pytest.mark.parametrize(
    "source",
    [
        # A non-MCP framework using the same decorator shape.
        """
import flask
app = flask.Flask(__name__)

@app.route("/x")
def handler():
    return "x"
""",
        # Plain helpers with no decorator at all.
        """
def helper(x):
    return x * 2
""",
    ],
    ids=["flask_route", "undecorated_helper"],
)
def test_lookalike_decorators_are_not_mistaken_for_capabilities(source):
    """Matching on any ``@name.verb()`` would sweep in unrelated frameworks."""
    assert capabilities(source) == {}
