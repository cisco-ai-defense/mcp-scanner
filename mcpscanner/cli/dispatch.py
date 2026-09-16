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

"""Subcommand to handler lookup."""

from typing import Awaitable, Callable, Dict

from .context import CommandContext, CommandResult
from .commands import (
    behavioral,
    configs,
    instructions,
    legacy_remote,
    package_scan,
    prompts,
    remote,
    resources,
    static,
    stdio,
    virustotal,
    vuln_pkgs,
)

Handler = Callable[[CommandContext], Awaitable[CommandResult]]

HANDLERS: Dict[str, Handler] = {
    "static": static.run,
    "remote": remote.run,
    "stdio": stdio.run,
    "config": configs.run_config_file,
    "known-configs": configs.run_known_configs,
    "prompts": prompts.run,
    "resources": resources.run,
    "instructions": instructions.run,
    "virustotal": virustotal.run,
    "behavioral": behavioral.run,
    "pypi-scan": package_scan.run_pypi,
    "npm-scan": package_scan.run_npm,
    "vulnerable-package": vuln_pkgs.run,
}


def resolve(ctx: CommandContext) -> Handler:
    """Pick the handler for this invocation.

    Without a subcommand the meaning comes from the global flags, which is
    how the CLI worked before subcommands existed.
    """
    handler = HANDLERS.get(getattr(ctx.args, "cmd", None))
    if handler is not None:
        return handler
    if ctx.args.stdio_command:
        return stdio.run
    if ctx.args.scan_known_configs or ctx.args.config_path:
        return configs.run_legacy
    return legacy_remote.run


async def run_command(ctx: CommandContext) -> CommandResult:
    """Execute the handler this invocation selects."""
    return await resolve(ctx)(ctx)
