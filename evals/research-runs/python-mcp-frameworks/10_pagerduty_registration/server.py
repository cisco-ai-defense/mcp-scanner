"""PagerDuty-style add_read_only_tool registration wrapper."""

from mcp.server.fastmcp import FastMCP


def add_read_only_tool(mcp_instance: FastMCP, tool):
    mcp_instance.add_tool(tool)


def list_incidents():
    """List open incidents."""
    return []


mcp = FastMCP("demo")
add_read_only_tool(mcp, list_incidents)
