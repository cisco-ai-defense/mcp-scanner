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
Script to run behavioral MCP scanner against evaluation data.

This script scans all malicious MCP server implementations in the data directory
to evaluate the behavioral analyzer's detection capabilities.
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

from mcpscanner import Config
from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer

# Top-level directories under data/ that nest `data/<language>/<threat-category>/...`
# rather than `data/<threat-category>/*.py`.
LANGUAGE_ROOTS: frozenset[str] = frozenset(
    {"javascript", "typescript", "go", "rust", "csharp"}
)

LANG_EXTENSIONS: Dict[str, Sequence[str]] = {
    "javascript": (".js",),
    "typescript": (".ts",),
    "go": (".go",),
    "rust": (".rs",),
    "csharp": (".cs",),
}


async def scan_file(analyzer: BehavioralCodeAnalyzer, filepath: Path) -> Dict[str, Any]:
    """Scan a single file and return results."""
    try:
        # Read the file content
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Analyze the file with context
        context = {"file_path": str(filepath), "file_name": filepath.name}
        findings = await analyzer.analyze(content, context)

        # ``analyze()`` now returns a SAFE-severity SecurityFinding for
        # every scanned tool that came back clean, so ``len(findings)``
        # is no longer a valid safety signal (it now counts all scanned
        # tools, safe + unsafe). Classify by severity instead, and keep
        # the eval JSON shape backward compatible by reporting only the
        # real (non-SAFE) mismatches in the count.
        mismatch_findings = [f for f in findings if f.severity != "SAFE"]

        return {
            "file": str(filepath.relative_to(Path(__file__).parent.parent)),
            "status": "completed",
            "is_safe": len(mismatch_findings) == 0,
            "findings_count": len(mismatch_findings),
            "findings": [
                {
                    "severity": f.severity,
                    "summary": f.summary,
                    "threat_category": f.threat_category,
                }
                for f in mismatch_findings
            ],
        }
    except Exception as e:
        return {
            "file": str(filepath.relative_to(Path(__file__).parent.parent)),
            "status": "error",
            "error": str(e),
        }


async def scan_category(
    analyzer: BehavioralCodeAnalyzer,
    category_dir: Path,
    *,
    extensions: Sequence[str],
    scan_label: str | None = None,
) -> List[Dict[str, Any]]:
    """Scan evaluation files under a threat-category directory."""
    label = scan_label if scan_label else category_dir.name
    targets: List[Path] = []
    for ext in extensions:
        targets.extend(sorted(category_dir.glob(f"*{ext}")))

    results: List[Dict[str, Any]] = []
    display = (
        str(category_dir.relative_to(category_dir.parent.parent))
        if "data" in category_dir.parts
        else category_dir.name
    )

    print(f"\n📁 Scanning {label} ({display}): {len(targets)} files")

    for file_path in targets:
        print(f"  🔍 {file_path.name}...", end=" ")
        result = await scan_file(analyzer, file_path)
        results.append(result)

        if result.get("status") == "error":
            print("❌ ERROR")
        elif result.get("is_safe"):
            print("⚠️  MISSED (no findings)")
        else:
            print(f"✅ DETECTED ({result['findings_count']} findings)")

    return results


def _parse_cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run BehavioralCodeAnalyzer across eval corpus (Python plus optional languages).",
    )
    parser.add_argument(
        "--languages",
        default=None,
        metavar="LIST",
        help=(
            "Comma-separated extra language roots under data/, e.g. "
            "'javascript,typescript,go,rust,csharp'. "
            "Each layout is data/<language>/<threat-category>/*.{ext}"
        ),
    )
    parser.add_argument(
        "--all-languages",
        action="store_true",
        help=f"Equivalent to --languages {','.join(sorted(LANG_EXTENSIONS))}",
    )
    parser.add_argument(
        "--no-python",
        action="store_true",
        help="Skip legacy Python corpus at data/<threat-category>/*.py",
    )
    return parser.parse_args()


async def main() -> int:
    """Main function to run behavioral scans."""
    opts = _parse_cli()
    langs: List[str] = []
    if opts.all_languages:
        langs = sorted(LANG_EXTENSIONS.keys())
    elif opts.languages:
        langs = [s.strip().lower() for s in opts.languages.split(",") if s.strip()]

    for lang in langs:
        if lang not in LANG_EXTENSIONS:
            print(f"❌ Unknown language root '{lang}'. Expected one of:")
            print(f"   {', '.join(sorted(LANG_EXTENSIONS))}")
            return 2

    print("=" * 80)
    print("Behavioral Analysis Evaluation Scanner")
    print("=" * 80)

    # Get the data directory
    script_dir = Path(__file__).parent
    data_dir = script_dir.parent / "data"

    if not data_dir.exists():
        print(f"❌ Error: Data directory not found: {data_dir}")
        sys.exit(1)

    print(f"\n📂 Data directory: {data_dir}")

    # Create analyzer with configuration from environment
    config = Config(
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    # Check if LLM is configured
    if not config.llm_provider_api_key:
        print("\n❌ Error: LLM configuration required for behavioral analysis")
        print("\nPlease set the following environment variables:")
        print("  export MCP_SCANNER_LLM_API_KEY='your_api_key'")
        print("  export MCP_SCANNER_LLM_MODEL='azure/gpt-4.1'  # or other model")
        print(
            "  export MCP_SCANNER_LLM_BASE_URL='https://your-endpoint.openai.azure.com/'"
        )
        print("  export MCP_SCANNER_LLM_API_VERSION='2024-02-15-preview'")
        sys.exit(1)

    print(f"🤖 LLM Model: {config.llm_model}")

    analyzer = BehavioralCodeAnalyzer(config)

    all_results: Dict[str, List[Dict[str, Any]]] = {}
    total_files = total_detected = total_missed = total_errors = 0

    corpus_labels: List[str] = []

    # Legacy Python: data/<threat-category>/*.py  (excluding language-folder roots)
    if not opts.no_python:
        py_categories = sorted(
            [
                d
                for d in data_dir.iterdir()
                if d.is_dir() and d.name not in LANGUAGE_ROOTS
            ]
        )
        corpus_labels.append(f"python ({len(py_categories)} categories)")
        for category_dir in py_categories:
            key = category_dir.name
            category_results = await scan_category(
                analyzer,
                category_dir,
                extensions=(".py",),
                scan_label=f"{key} [python]",
            )
            all_results.setdefault(key, []).extend(category_results)
            total_files += len(category_results)
            for result in category_results:
                if result.get("status") == "error":
                    total_errors += 1
                elif result.get("is_safe"):
                    total_missed += 1
                else:
                    total_detected += 1

    # Optional multi-language subtrees: data/<language>/<threat-category>/*
    for lang in langs:
        exts = LANG_EXTENSIONS[lang]
        lang_root = data_dir / lang
        if not lang_root.is_dir():
            print(f"\n⚠️  Skip missing language folder: {lang_root}")
            continue
        corpus_labels.append(lang)
        for category_dir in sorted(d for d in lang_root.iterdir() if d.is_dir()):
            key = f"{lang}/{category_dir.name}"
            category_results = await scan_category(
                analyzer,
                category_dir,
                extensions=exts,
                scan_label=key,
            )
            all_results.setdefault(key, []).extend(category_results)
            total_files += len(category_results)
            for result in category_results:
                if result.get("status") == "error":
                    total_errors += 1
                elif result.get("is_safe"):
                    total_missed += 1
                else:
                    total_detected += 1

    print(f"\n📊 Corpora scanned: {', '.join(corpus_labels) if corpus_labels else 'none'}")

    detection_rate_pct: float | None = None

    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total files scanned: {total_files}")
    print(f"✅ Detected (with findings): {total_detected}")
    print(f"⚠️  Missed (no findings): {total_missed}")
    print(f"❌ Errors: {total_errors}")

    if total_files > 0:
        detection_rate_pct = (total_detected / total_files) * 100
        print(f"\n🎯 Detection Rate: {detection_rate_pct:.1f}%")

    detection_rate_display = (
        f"{detection_rate_pct:.1f}%" if detection_rate_pct is not None else "N/A"
    )

    # Save detailed results to JSON
    output_file = script_dir / "scan_results.json"
    with open(output_file, "w") as f:
        json.dump(
            {
                "summary": {
                    "total_files": total_files,
                    "detected": total_detected,
                    "missed": total_missed,
                    "errors": total_errors,
                    "detection_rate": detection_rate_display,
                },
                "results_by_category": all_results,
            },
            f,
            indent=2,
        )

    print(f"\n💾 Detailed results saved to: {output_file}")
    print("=" * 80)

    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
