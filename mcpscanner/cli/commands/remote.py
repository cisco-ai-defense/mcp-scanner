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

"""``remote``: scan the tools exposed by an HTTP MCP server."""

from typing import Any, Optional

from mcpscanner import Scanner
from mcpscanner.core.report_generator import results_to_json

from ..config import _build_config, _create_auth_with_headers, _parse_custom_headers
from ..context import CommandContext


async def run(ctx: CommandContext) -> Optional[Any]:
    """Scan every tool advertised by a remote MCP server."""
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    # Parse custom headers and create auth
    custom_headers = _parse_custom_headers(getattr(args, "custom_headers", None))
    auth = _create_auth_with_headers(args.bearer_token, custom_headers)
    results_raw = await scanner.scan_remote_server_tools(
        args.server_url, auth=auth, analyzers=selected_analyzers
    )
    results = await results_to_json(results_raw)
    return results
