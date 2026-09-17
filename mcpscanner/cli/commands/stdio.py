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

"""``stdio``: launch a local MCP server over stdio and scan its tools."""

from typing import Any, Optional

from mcpscanner import Scanner
from mcpscanner.core.mcp_models import StdioServer
from mcpscanner.core.report_generator import results_to_json

from ..config import _build_config
from ..context import CommandContext


async def run(ctx: CommandContext) -> Optional[Any]:
    """Spawn the configured command and scan the server it speaks for.

    Reached both from the ``stdio`` subcommand and from the legacy
    subcommand-less ``--stdio-command`` invocation, which were identical.
    """
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    env_dict = {}
    for item in args.stdio_env or []:
        if "=" in item:
            k, v = item.split("=", 1)
            env_dict[k] = v
    # Parse comma-separated --stdio-args and/or repeated --stdio-arg
    stdio_args = []
    if args.stdio_args:
        stdio_args.extend([a for a in args.stdio_args.split(",") if a])
    if getattr(args, "stdio_arg", None):
        stdio_args.extend(args.stdio_arg)

    # Handle stderr redirection
    stderr_file = getattr(args, "stderr_file", None)
    errlog = None
    if stderr_file:
        errlog = open(stderr_file, "w")

    stdio = StdioServer(
        command=args.stdio_command,
        args=stdio_args,
        env=env_dict or None,
        expand_vars=args.expand_vars,
    )
    try:
        if args.stdio_tool:
            scan_result = await scanner.scan_stdio_server_tool(
                stdio, args.stdio_tool, analyzers=selected_analyzers, errlog=errlog
            )
            results = await results_to_json([scan_result])
        else:
            scan_results = await scanner.scan_stdio_server_tools(
                stdio, analyzers=selected_analyzers, errlog=errlog
            )
            results = await results_to_json(scan_results)
    finally:
        if errlog:
            errlog.close()
    return results
