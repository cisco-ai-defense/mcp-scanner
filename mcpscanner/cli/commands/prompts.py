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

"""``prompts``: scan prompts published by a remote MCP server."""

from typing import Any, Optional

from mcpscanner import Scanner

from ..config import _build_config, _create_auth_with_headers, _parse_custom_headers
from ..context import CommandContext


async def run(ctx: CommandContext) -> Optional[Any]:
    """Scan one named prompt, or all of them."""
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    # Parse custom headers and create auth
    custom_headers = _parse_custom_headers(
        getattr(args, "custom_headers", None)
    )
    auth = _create_auth_with_headers(args.bearer_token, custom_headers)

    if args.prompt_name:
        # Scan specific prompt
        result = await scanner.scan_remote_server_prompt(
            server_url=args.server_url,
            prompt_name=args.prompt_name,
            auth=auth,
            analyzers=selected_analyzers,
        )
        # Convert PromptScanResult to dict format
        results = [
            {
                "prompt_name": result.prompt_name,
                "prompt_description": result.prompt_description,
                "status": result.status,
                "is_safe": result.is_safe,
                "findings": [
                    {
                        "severity": f.severity,
                        "summary": f.summary,
                        "analyzer": f.analyzer,
                        "details": f.details,
                        "mcp_taxonomy": (
                            f.mcp_taxonomy
                            if hasattr(f, "mcp_taxonomy")
                            else None
                        ),
                    }
                    for f in result.findings
                ],
            }
        ]
    else:
        # Scan all prompts
        prompt_results = await scanner.scan_remote_server_prompts(
            server_url=args.server_url,
            auth=auth,
            analyzers=selected_analyzers,
        )
        results = [
            {
                "prompt_name": r.prompt_name,
                "prompt_description": r.prompt_description,
                "status": r.status,
                "is_safe": r.is_safe,
                "findings": [
                    {
                        "severity": f.severity,
                        "summary": f.summary,
                        "analyzer": f.analyzer,
                        "details": f.details,
                        "mcp_taxonomy": (
                            f.mcp_taxonomy
                            if hasattr(f, "mcp_taxonomy")
                            else None
                        ),
                    }
                    for f in r.findings
                ],
            }
            for r in prompt_results
        ]
    return results
