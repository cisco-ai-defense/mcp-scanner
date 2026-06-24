#!/usr/bin/env python3
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

"""
MCP Scanner SDK — PyPI Package Scanner Example

Demonstrates how to use the PyPIPackageScanner SDK to scan PyPI packages
inside a Docker sandbox. Docker must be installed and running.

Usage:
  python sdk_pypi_scanner.py flask
  python sdk_pypi_scanner.py requests --version 2.31.0
  python sdk_pypi_scanner.py fastapi -o results.json

Prerequisites:
  - Docker installed and running
  - MCP_SCANNER_LLM_API_KEY env var set (for behavioral analysis)
"""

import argparse
import json
import sys

from mcpscanner.core.pypi_scanner import (
    DockerNotAvailableError,
    PyPIPackageScanner,
    PyPIScanError,
)


def main():
    parser = argparse.ArgumentParser(
        description="MCP Scanner SDK — PyPI Package Scanner",
    )
    parser.add_argument("package", help="PyPI package name (e.g., flask)")
    parser.add_argument("--version", help="Specific version (default: latest)")
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild Docker image")

    args = parser.parse_args()

    try:
        scanner = PyPIPackageScanner()

        if args.rebuild:
            print("Rebuilding Docker scanner image...")
            scanner.build_image(force=True)

        spec = f"{args.package}=={args.version}" if args.version else args.package
        print(f"\n{'=' * 60}")
        print(f"  PyPI Package Scanner (Docker-sandboxed)")
        print(f"{'=' * 60}")
        print(f"  Package: {spec}")

        results = scanner.scan_package(
            package=args.package,
            version=args.version,
            verbose=args.verbose,
        )

        safe = results.get("is_safe", True)
        total = results.get("total_findings", 0)
        behavioral = results.get("behavioral_findings", 0)
        py_files = results.get("python_files_scanned", 0)

        print(f"  Files:   {py_files} Python files scanned")
        print(f"  Status:  {'SAFE' if safe else 'UNSAFE'}")
        print(f"  Findings: {total} total ({behavioral} behavioral)")
        print(f"{'=' * 60}\n")

        for i, finding in enumerate(results.get("findings", []), 1):
            severity = finding.get("severity", "UNKNOWN")
            analyzer = finding.get("analyzer", "unknown")
            summary = finding.get("summary", "")
            category = finding.get("threat_category", "")

            icon = "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
            print(f"  {i}. {icon} [{severity}] {category}")
            print(f"     Analyzer: {analyzer}")
            print(f"     Summary:  {summary}")
            print()

        if not results.get("findings"):
            print("  All checks passed — no threats or vulnerabilities detected.\n")

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"  Results saved to: {args.output}\n")

    except DockerNotAvailableError as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
    except PyPIScanError as e:
        print(f"\nScan Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
