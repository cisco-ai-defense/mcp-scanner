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

"""CLI entry point: parse, dispatch, render."""

import asyncio
import sys

from .context import CommandContext
from .dispatch import run_command
from .output import render
from .parser import build_parser
from .runtime import configure_runtime


async def main() -> None:
    """Run one CLI invocation end to end."""
    parser = build_parser()
    args = parser.parse_args()
    selected_analyzers = configure_runtime(parser, args)
    ctx = CommandContext(args=args, analyzers=selected_analyzers)

    try:
        results = await run_command(ctx)
    except Exception as e:
        print(f"Error during scanning: {e}", file=sys.stderr)
        sys.exit(1)

    # A handler returns None when it has already written its own output.
    if results is None:
        return

    render(ctx, results)


def cli_entry_point():
    """Entry point for the mcp-scanner CLI command."""
    import warnings

    # Suppress warnings from MCP library cleanup issues
    warnings.filterwarnings(
        "ignore", category=RuntimeWarning, message=".*coroutine.*never awaited.*"
    )
    warnings.filterwarnings(
        "ignore", category=RuntimeWarning, message=".*async.*generator.*"
    )

    # Suppress asyncio shutdown errors from MCP library cleanup bugs
    def custom_exception_handler(loop, context):
        exception = context.get("exception")
        message = context.get("message", "")

        # Suppress RuntimeError from MCP library task cleanup
        if isinstance(exception, RuntimeError) and "cancel scope" in str(exception):
            return
        # Suppress task destroyed warnings
        if "Task was destroyed but it is pending" in message:
            return
        # Suppress other MCP library cleanup errors
        if "streamablehttp_client" in message or "async_generator" in message:
            return
        # For other exceptions, use default handling
        loop.default_exception_handler(context)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_exception_handler(custom_exception_handler)

    try:
        loop.run_until_complete(main())
    finally:
        # Suppress warnings during loop close
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            loop.close()
