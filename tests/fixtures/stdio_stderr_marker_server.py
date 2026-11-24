"""Minimal stdio MCP server that writes a startup marker to stderr.

Used to prove --stderr-file captures the server process stderr. No tools are
registered, so tools/list is empty. The marker is written at import time,
before the stdio loop starts.
"""

import sys

from mcp.server.mcpserver import MCPServer

MARKER = "MCP_SCANNER_STDERR_MARKER"

sys.stderr.write(MARKER + "\n")
sys.stderr.flush()

mcp = MCPServer("stdio-stderr-marker")


if __name__ == "__main__":
    mcp.run()
