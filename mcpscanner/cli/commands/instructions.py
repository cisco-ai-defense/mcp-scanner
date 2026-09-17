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

"""``instructions``: scan a server's initialization instructions."""

from typing import Any, Optional

from mcpscanner import Scanner
from mcpscanner.core.auth import Auth

from ..config import _build_config
from ..context import CommandContext


async def run(ctx: CommandContext) -> Optional[Any]:
    """Scan the instructions string a server returns at initialization."""
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    auth = Auth.bearer(args.bearer_token) if args.bearer_token else None

    # Scan server instructions
    result = await scanner.scan_remote_server_instructions(
        server_url=args.server_url,
        auth=auth,
        analyzers=selected_analyzers,
    )
    # Convert InstructionsScanResult to dict format
    results = [
        {
            "instructions": result.instructions,
            "server_name": result.server_name,
            "protocol_version": result.protocol_version,
            "status": result.status,
            "is_safe": result.is_safe,
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
    return results
