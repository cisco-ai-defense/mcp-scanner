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

"""The subcommand-less invocation kept for backward compatibility."""

from typing import Any, Optional

from mcpscanner import Scanner
from mcpscanner.core.auth import Auth
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.report_generator import results_to_json

from ..config import _build_config
from ..context import CommandContext
from ..results import _run_behavioral_analyzer_on_source


async def run(ctx: CommandContext) -> Optional[Any]:
    """Scan a server URL (or a source path) given only global flags.

    Predates the subcommand interface; ``mcp-scanner --server-url ...``
    still has to work.
    """
    args = ctx.args
    selected_analyzers = ctx.analyzers

    # Check if behavioral analyzer with source path
    if AnalyzerEnum.BEHAVIORAL in selected_analyzers and args.source_path:
        # Run behavioral analyzer on source code
        return await _run_behavioral_analyzer_on_source(args.source_path)

    # Run the security scan against a server URL
    if args.bearer_token:
        cfg = _build_config(selected_analyzers)
        scanner = Scanner(cfg, rules_dir=args.rules_path)
        results_raw = await scanner.scan_remote_server_tools(
            args.server_url,
            auth=Auth.bearer(args.bearer_token),
            analyzers=selected_analyzers,
        )
        return await results_to_json(results_raw)

    cfg = _build_config(selected_analyzers, endpoint_url=args.endpoint_url)
    scanner = Scanner(cfg, rules_dir=args.rules_path)
    auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
    results_raw = await scanner.scan_remote_server_tools(
        args.server_url, auth=auth, analyzers=selected_analyzers
    )
    return await results_to_json(results_raw)
