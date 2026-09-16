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

"""``config`` and ``known-configs``: scan servers named by MCP client config."""

import json
from typing import Any, Optional

from mcpscanner import Scanner
from mcpscanner.core.auth import Auth
from mcpscanner.core.report_generator import results_to_json

from ..config import _build_config
from ..context import CommandContext


async def run_config_file(ctx: CommandContext) -> Optional[Any]:
    """Scan every server declared in one MCP client config file."""
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
    scan_results = await scanner.scan_mcp_config_file(
        args.config_path,
        analyzers=selected_analyzers,
        auth=auth,
        expand_vars_default=args.expand_vars,
    )
    results = await results_to_json(scan_results)
    return results


async def run_known_configs(ctx: CommandContext) -> Optional[Any]:
    """Scan every server found in the well-known MCP client config paths."""
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
    results_by_cfg = await scanner.scan_well_known_mcp_configs(
        analyzers=selected_analyzers,
        auth=auth,
        expand_vars_default=args.expand_vars,
    )
    if args.raw:
        output = {}
        for cfg_path, scan_results in results_by_cfg.items():
            output[cfg_path] = await results_to_json(scan_results)
        print(json.dumps(output, indent=2))
        return
    flattened = []
    for scan_results in results_by_cfg.values():
        flattened.extend(scan_results)
    results = await results_to_json(flattened)
    return results


async def run_legacy(ctx: CommandContext) -> Optional[Any]:
    """The subcommand-less ``--config-path`` / ``--scan-known-configs`` path.

    Not quite the two subcommands above: this one stamps each result with
    the config file it came from so the report can attribute servers.
    """
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    if args.config_path:
        auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
        scan_results = await scanner.scan_mcp_config_file(
            args.config_path,
            analyzers=selected_analyzers,
            auth=auth,
            expand_vars_default=args.expand_vars,
        )
        results = await results_to_json(scan_results)
    else:
        auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
        results_by_cfg = await scanner.scan_well_known_mcp_configs(
            analyzers=selected_analyzers,
            auth=auth,
            expand_vars_default=args.expand_vars,
        )
        if args.raw:
            output = {}
            for cfg_path, scan_results in results_by_cfg.items():
                output[cfg_path] = await results_to_json(scan_results)
            print(json.dumps(output, indent=2))
            return
        flattened = []
        for cfg_path, scan_results in results_by_cfg.items():
            # Add config path and server info to each result
            for result in scan_results:
                # Extract server name from config path for display
                config_name = cfg_path.split("/")[-1] if "/" in cfg_path else cfg_path
                result.server_source = f"{config_name}"
            flattened.extend(scan_results)
        results = await results_to_json(flattened)
    return results
