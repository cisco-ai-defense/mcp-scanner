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

"""``resources``: scan resources published by a remote MCP server."""

from typing import Any, Optional

from mcpscanner import Scanner

from ..config import _build_config, _create_auth_with_headers, _parse_custom_headers
from ..context import CommandContext


async def run(ctx: CommandContext) -> Optional[Any]:
    """Scan one named resource URI, or all of them."""
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    # Parse custom headers and create auth
    custom_headers = _parse_custom_headers(getattr(args, "custom_headers", None))
    auth = _create_auth_with_headers(args.bearer_token, custom_headers)

    # Parse MIME types
    allowed_mime_types = [m.strip() for m in args.mime_types.split(",")]

    if args.resource_uri:
        # Scan specific resource
        result = await scanner.scan_remote_server_resource(
            server_url=args.server_url,
            resource_uri=args.resource_uri,
            auth=auth,
            analyzers=selected_analyzers,
            allowed_mime_types=allowed_mime_types,
        )
        # Convert ResourceScanResult to dict format
        results = [
            {
                "resource_uri": str(result.resource_uri),
                "resource_name": result.resource_name,
                "resource_mime_type": result.resource_mime_type,
                "status": result.status,
                "is_safe": (result.is_safe if result.status == "completed" else None),
                "findings": [
                    {
                        "severity": f.severity,
                        "summary": f.summary,
                        "analyzer": f.analyzer,
                        "details": f.details,
                        "mcp_taxonomy": (
                            f.mcp_taxonomy if hasattr(f, "mcp_taxonomy") else None
                        ),
                    }
                    for f in result.findings
                ],
            }
        ]
    else:
        # Scan all resources
        resource_results = await scanner.scan_remote_server_resources(
            server_url=args.server_url,
            auth=auth,
            analyzers=selected_analyzers,
            allowed_mime_types=allowed_mime_types,
        )
        results = [
            {
                "resource_uri": str(r.resource_uri),
                "resource_name": r.resource_name,
                "resource_mime_type": r.resource_mime_type,
                "status": r.status,
                "is_safe": r.is_safe if r.status == "completed" else None,
                "findings": [
                    {
                        "severity": f.severity,
                        "summary": f.summary,
                        "analyzer": f.analyzer,
                        "details": f.details,
                        "mcp_taxonomy": (
                            f.mcp_taxonomy if hasattr(f, "mcp_taxonomy") else None
                        ),
                    }
                    for f in r.findings
                ],
            }
            for r in resource_results
        ]
    return results
