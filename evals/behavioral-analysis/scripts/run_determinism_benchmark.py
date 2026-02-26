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
Determinism benchmark for behavioral code scanning.

Runs each eval file N times (default 100) and tracks whether results change
across runs. Reports per-file consistency metrics:
- How many unique result signatures were seen
- How many times each result variant appeared
- Which fields changed (mismatch_detected, threat_name, severity, findings_count)

Usage:
    export MCP_SCANNER_LLM_API_KEY='your_key'
    export MCP_SCANNER_LLM_BASE_URL='https://your-endpoint.openai.azure.com/'
    export MCP_SCANNER_LLM_API_VERSION='2024-02-15-preview'
    export MCP_SCANNER_LLM_MODEL='azure/gpt-4.1'

    uv run python evals/behavioral-analysis/scripts/run_determinism_benchmark.py --runs 100
    uv run python evals/behavioral-analysis/scripts/run_determinism_benchmark.py --runs 10 --category tool-poisoning
    uv run python evals/behavioral-analysis/scripts/run_determinism_benchmark.py --runs 5 --file evals/behavioral-analysis/data/tool-poisoning/response_poisoning_content_injection.py
"""

import argparse
import asyncio
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mcpscanner import Config
from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer


def normalize_finding(finding) -> Dict[str, str]:
    """Extract a comparable dict from a SecurityFinding."""
    return {
        "severity": finding.severity,
        "threat_category": finding.threat_category,
        "summary_prefix": finding.summary[:80] if finding.summary else "",
    }


def result_signature(findings_list: List[Dict]) -> str:
    """Create a hashable signature from findings for comparison."""
    if not findings_list:
        return "SAFE:no_findings"
    # Sort by threat_category for stable ordering
    sorted_findings = sorted(findings_list, key=lambda f: f.get("threat_category", ""))
    parts = []
    for f in sorted_findings:
        parts.append(f"{f['severity']}|{f['threat_category']}")
    return ";".join(parts)


async def scan_file_once(
    analyzer: BehavioralCodeAnalyzer, filepath: Path
) -> Tuple[str, List[Dict], Optional[str]]:
    """Scan a file once and return (signature, findings_list, error)."""
    try:
        context = {"file_path": str(filepath), "file_name": filepath.name}
        findings = await analyzer.analyze(str(filepath), context)

        findings_list = [normalize_finding(f) for f in findings]
        sig = result_signature(findings_list)
        return sig, findings_list, None
    except Exception as e:
        return "ERROR", [], str(e)


async def benchmark_file(
    config: Config, filepath: Path, num_runs: int, file_index: int, total_files: int
) -> Dict[str, Any]:
    """Run benchmark for a single file across N runs."""
    relative_path = str(filepath)
    # Try to make path relative for display
    try:
        data_root = Path(__file__).parent.parent / "data"
        relative_path = str(filepath.relative_to(data_root))
    except ValueError:
        pass

    print(f"\n[{file_index}/{total_files}] {relative_path}")
    print(f"  Running {num_runs} iterations...", end="", flush=True)

    signatures = []
    all_findings = []
    errors = []
    run_details = []

    for i in range(num_runs):
        # Create a fresh analyzer each run to avoid any caching
        analyzer = BehavioralCodeAnalyzer(config)

        start = time.time()
        sig, findings, error = await scan_file_once(analyzer, filepath)
        elapsed = time.time() - start

        run_detail = {
            "run": i + 1,
            "signature": sig,
            "findings_count": len(findings),
            "elapsed_seconds": round(elapsed, 2),
        }
        if error:
            run_detail["error"] = error
            errors.append(error)

        signatures.append(sig)
        all_findings.append(findings)
        run_details.append(run_detail)

        # Progress indicator
        if (i + 1) % 10 == 0:
            print(f" {i + 1}", end="", flush=True)
        elif (i + 1) % 5 == 0:
            print(".", end="", flush=True)

    print()  # newline after progress

    # Analyze consistency
    sig_counts = Counter(signatures)
    unique_signatures = len(sig_counts)
    most_common_sig, most_common_count = sig_counts.most_common(1)[0]
    is_deterministic = unique_signatures == 1

    # Collect all unique threat_categories and severities seen
    all_threat_cats = set()
    all_severities = set()
    all_findings_counts = set()
    for findings in all_findings:
        all_findings_counts.add(len(findings))
        for f in findings:
            all_threat_cats.add(f.get("threat_category", ""))
            all_severities.add(f.get("severity", ""))

    result = {
        "file": relative_path,
        "num_runs": num_runs,
        "is_deterministic": is_deterministic,
        "unique_signatures": unique_signatures,
        "most_common_signature": most_common_sig,
        "most_common_count": most_common_count,
        "consistency_rate": round(most_common_count / num_runs * 100, 1),
        "signature_distribution": dict(sig_counts),
        "unique_severities": sorted(all_severities),
        "unique_threat_categories": sorted(all_threat_cats),
        "unique_findings_counts": sorted(all_findings_counts),
        "error_count": len(errors),
    }

    # Print summary for this file
    if is_deterministic:
        print(f"  ✅ DETERMINISTIC ({most_common_sig}) — {num_runs}/{num_runs} consistent")
    else:
        print(f"  ⚠️  NON-DETERMINISTIC — {unique_signatures} variants across {num_runs} runs:")
        for sig, count in sig_counts.most_common():
            pct = round(count / num_runs * 100, 1)
            print(f"     {count}x ({pct}%): {sig}")
        if len(all_severities) > 1:
            print(f"     Severities seen: {sorted(all_severities)}")
        if len(all_findings_counts) > 1:
            print(f"     Findings counts: {sorted(all_findings_counts)}")

    if errors:
        print(f"  ❌ {len(errors)} errors occurred")

    return result


def collect_files(
    data_dir: Path, category: Optional[str] = None, single_file: Optional[str] = None
) -> List[Path]:
    """Collect eval files to benchmark."""
    if single_file:
        p = Path(single_file)
        if not p.is_absolute():
            p = Path.cwd() / p
        if not p.exists():
            print(f"❌ File not found: {p}")
            sys.exit(1)
        return [p]

    if category:
        cat_dir = data_dir / category
        if not cat_dir.exists():
            print(f"❌ Category not found: {cat_dir}")
            print(f"   Available: {sorted(d.name for d in data_dir.iterdir() if d.is_dir())}")
            sys.exit(1)
        return sorted(cat_dir.glob("*.py"))

    # All categories
    files = []
    for cat_dir in sorted(data_dir.iterdir()):
        if cat_dir.is_dir():
            files.extend(sorted(cat_dir.glob("*.py")))
    return files


async def main():
    parser = argparse.ArgumentParser(
        description="Determinism benchmark for behavioral code scanning"
    )
    parser.add_argument(
        "--runs", type=int, default=100, help="Number of runs per file (default: 100)"
    )
    parser.add_argument(
        "--category", type=str, default=None,
        help="Only benchmark a specific threat category (e.g., tool-poisoning)"
    )
    parser.add_argument(
        "--file", type=str, default=None,
        help="Only benchmark a single file"
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output JSON file path (default: auto-generated in scripts/)"
    )
    args = parser.parse_args()

    print("=" * 80)
    print("Behavioral Code Scanning — Determinism Benchmark")
    print("=" * 80)

    # Config
    config = Config(
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    if not config.llm_provider_api_key:
        print("\n❌ Error: LLM configuration required.")
        print("  export MCP_SCANNER_LLM_API_KEY='your_key'")
        print("  export MCP_SCANNER_LLM_MODEL='azure/gpt-4.1'")
        print("  export MCP_SCANNER_LLM_BASE_URL='https://your-endpoint.openai.azure.com/'")
        print("  export MCP_SCANNER_LLM_API_VERSION='2024-02-15-preview'")
        sys.exit(1)

    print(f"🤖 Model: {config.llm_model}")
    print(f"🔄 Runs per file: {args.runs}")

    # Collect files
    data_dir = Path(__file__).parent.parent / "data"
    files = collect_files(data_dir, args.category, args.file)
    print(f"📂 Files to benchmark: {len(files)}")
    print(f"📊 Total LLM calls: ~{len(files) * args.runs}")

    # Estimate time
    est_seconds = len(files) * args.runs * 8  # ~8s per call estimate
    est_hours = est_seconds / 3600
    if est_hours > 1:
        print(f"⏱️  Estimated time: ~{est_hours:.1f} hours")
    else:
        print(f"⏱️  Estimated time: ~{est_seconds / 60:.0f} minutes")

    # Run benchmarks
    start_time = time.time()
    all_results = []
    deterministic_count = 0
    non_deterministic_count = 0

    for i, filepath in enumerate(files, 1):
        result = await benchmark_file(config, filepath, args.runs, i, len(files))
        all_results.append(result)
        if result["is_deterministic"]:
            deterministic_count += 1
        else:
            non_deterministic_count += 1

    total_time = time.time() - start_time

    # Summary
    print("\n" + "=" * 80)
    print("DETERMINISM BENCHMARK RESULTS")
    print("=" * 80)
    print(f"Total files: {len(all_results)}")
    print(f"Runs per file: {args.runs}")
    print(f"Total time: {total_time / 60:.1f} minutes")
    print(f"✅ Deterministic: {deterministic_count} ({deterministic_count / len(all_results) * 100:.1f}%)")
    print(f"⚠️  Non-deterministic: {non_deterministic_count} ({non_deterministic_count / len(all_results) * 100:.1f}%)")

    # List non-deterministic files
    if non_deterministic_count > 0:
        print(f"\n--- Non-deterministic files ---")
        non_det = [r for r in all_results if not r["is_deterministic"]]
        non_det.sort(key=lambda r: r["consistency_rate"])
        for r in non_det:
            print(f"  {r['file']}: {r['consistency_rate']}% consistent, {r['unique_signatures']} variants")
            for sig, count in sorted(
                r["signature_distribution"].items(), key=lambda x: -x[1]
            ):
                print(f"    {count}x: {sig}")

    # Consistency histogram
    print(f"\n--- Consistency Rate Distribution ---")
    buckets = {"100%": 0, "90-99%": 0, "80-89%": 0, "70-79%": 0, "<70%": 0}
    for r in all_results:
        rate = r["consistency_rate"]
        if rate == 100:
            buckets["100%"] += 1
        elif rate >= 90:
            buckets["90-99%"] += 1
        elif rate >= 80:
            buckets["80-89%"] += 1
        elif rate >= 70:
            buckets["70-79%"] += 1
        else:
            buckets["<70%"] += 1
    for bucket, count in buckets.items():
        bar = "█" * count
        print(f"  {bucket:>8}: {count:>3} {bar}")

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output:
        output_file = Path(args.output)
    else:
        output_file = Path(__file__).parent / f"determinism_results_{timestamp}.json"

    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "model": config.llm_model,
            "runs_per_file": args.runs,
            "total_files": len(all_results),
            "total_time_seconds": round(total_time, 1),
            "category_filter": args.category,
            "file_filter": args.file,
        },
        "summary": {
            "deterministic_files": deterministic_count,
            "non_deterministic_files": non_deterministic_count,
            "determinism_rate": round(
                deterministic_count / len(all_results) * 100, 1
            ) if all_results else 0,
            "avg_consistency_rate": round(
                sum(r["consistency_rate"] for r in all_results) / len(all_results), 1
            ) if all_results else 0,
        },
        "results": all_results,
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n💾 Results saved to: {output_file}")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
