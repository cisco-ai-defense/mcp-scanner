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

"""``pypi-scan`` and ``npm-scan``: scan a published package.

The two subcommands differ only in which scanner class they construct, which
exception type signals a scan failure, and how a version is spelled in the
package specifier.
"""

import json
import sys
from typing import Any, Optional

from ..context import CommandContext
from ..results import _package_scan_to_tool_results


async def _run(
    ctx: CommandContext,
    *,
    scanner_cls: type,
    scan_error: type[Exception],
    version_separator: str,
    ecosystem_label: str,
) -> Optional[Any]:
    """Fetch and scan one published package, in Docker unless opted out."""
    from mcpscanner.core.pypi_scanner import (
        DockerNotAvailableError,
        LLMNotConfiguredError,
    )

    args = ctx.args
    use_docker = not getattr(args, "no_docker", False)
    try:
        scanner = scanner_cls(use_docker=use_docker)
        if use_docker and getattr(args, "rebuild_image", False):
            scanner.build_image(force=True)

        if use_docker:
            scan_results = scanner.scan_package(
                package=args.package,
                version=getattr(args, "version", None),
                verbose=getattr(args, "verbose", False),
            )
        else:
            scan_results = await scanner.scan_package_async(
                package=args.package,
                version=getattr(args, "version", None),
                verbose=getattr(args, "verbose", False),
            )

        pkg_spec = args.package
        if getattr(args, "version", None):
            pkg_spec = f"{args.package}{version_separator}{args.version}"

        results = _package_scan_to_tool_results(
            scan_results=scan_results,
            pkg_spec=pkg_spec,
            ecosystem_label=ecosystem_label,
        )

        if any(
            row.get("status") == "error" or row.get("is_safe") is None
            for row in results
        ):
            print(
                "Scan Error: package scan could not be completed reliably",
                file=sys.stderr,
            )
            sys.exit(1)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            if args.verbose:
                print(f"Results saved to {args.output}")

        return results

    except DockerNotAvailableError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except LLMNotConfiguredError as e:
        print(f"Config Error: {e}", file=sys.stderr)
        sys.exit(2)
    except scan_error as e:
        print(f"Scan Error: {e}", file=sys.stderr)
        sys.exit(1)


async def run_pypi(ctx: CommandContext) -> Optional[Any]:
    """Scan a package published to PyPI."""
    from mcpscanner.core.pypi_scanner import PyPIPackageScanner, PyPIScanError

    return await _run(
        ctx,
        scanner_cls=PyPIPackageScanner,
        scan_error=PyPIScanError,
        version_separator="==",
        ecosystem_label="PyPI",
    )


async def run_npm(ctx: CommandContext) -> Optional[Any]:
    """Scan a package published to the npm registry."""
    from mcpscanner.core.npm_scanner import NPMPackageScanner, NPMScanError

    return await _run(
        ctx,
        scanner_cls=NPMPackageScanner,
        scan_error=NPMScanError,
        version_separator="@",
        ecosystem_label="npm",
    )
