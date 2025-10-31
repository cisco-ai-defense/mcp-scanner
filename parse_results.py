#!/usr/bin/env python3
"""Parse scan results and generate summary report."""

import json
import re
from pathlib import Path
from collections import defaultdict

def extract_json_from_output(content: str) -> dict:
    """Extract JSON from mixed log/JSON output.
    
    Args:
        content: Raw output with logs and JSON
        
    Returns:
        Parsed JSON dict or None
    """
    # Find the JSON array at the end (starts with [ and ends with ])
    match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def parse_scan_results(results_dir: Path) -> dict:
    """Parse all scan result files.
    
    Args:
        results_dir: Directory containing scan results
        
    Returns:
        Summary dict
    """
    summary = {
        "total_repos": 0,
        "repos_with_findings": [],
        "safe_repos": [],
        "parse_errors": [],
        "findings_by_severity": defaultdict(list),
        "all_findings": []
    }
    
    for result_file in sorted(results_dir.glob("*_scan.json")):
        repo_name = result_file.stem.replace("_scan", "")
        summary["total_repos"] += 1
        
        try:
            content = result_file.read_text()
            data = extract_json_from_output(content)
            
            if not data:
                summary["parse_errors"].append(repo_name)
                continue
            
            # data is a list of tools
            has_findings = False
            for tool in data:
                if not tool.get("is_safe", True):
                    has_findings = True
                    findings = tool.get("findings", {})
                    
                    for analyzer_name, analyzer_findings in findings.items():
                        severity = analyzer_findings.get("severity", "UNKNOWN")
                        threat_summary = analyzer_findings.get("threat_summary", "")
                        
                        finding_info = {
                            "repo": repo_name,
                            "tool": tool.get("tool_name", "unknown"),
                            "file": analyzer_findings.get("source_file", ""),
                            "severity": severity,
                            "summary": threat_summary
                        }
                        
                        summary["findings_by_severity"][severity].append(finding_info)
                        summary["all_findings"].append(finding_info)
            
            if has_findings:
                summary["repos_with_findings"].append(repo_name)
            else:
                summary["safe_repos"].append(repo_name)
                
        except Exception as e:
            print(f"Error parsing {repo_name}: {e}")
            summary["parse_errors"].append(repo_name)
    
    return summary


def print_summary(summary: dict):
    """Print formatted summary report."""
    print("\n" + "="*80)
    print("MCP REPOSITORY SCAN SUMMARY")
    print("="*80)
    
    print(f"\n📊 OVERVIEW:")
    print(f"  Total repositories scanned: {summary['total_repos']}")
    print(f"  ✅ Safe repositories: {len(summary['safe_repos'])}")
    print(f"  🚨 Repositories with findings: {len(summary['repos_with_findings'])}")
    print(f"  ⚠️  Parse errors: {len(summary['parse_errors'])}")
    
    # Severity breakdown
    print(f"\n🔍 FINDINGS BY SEVERITY:")
    for severity in ["HIGH", "MEDIUM", "LOW"]:
        count = len(summary['findings_by_severity'][severity])
        if count > 0:
            emoji = "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
            print(f"  {emoji} {severity}: {count} finding(s)")
    
    # High severity findings
    high_findings = summary['findings_by_severity']['HIGH']
    if high_findings:
        print(f"\n🔴 HIGH SEVERITY FINDINGS ({len(high_findings)}):")
        for finding in high_findings:
            print(f"\n  Repository: {finding['repo']}")
            print(f"  Tool: {finding['tool']}")
            print(f"  File: {Path(finding['file']).name if finding['file'] else 'N/A'}")
            print(f"  Issue: {finding['summary'][:200]}...")
    
    # Medium severity findings
    medium_findings = summary['findings_by_severity']['MEDIUM']
    if medium_findings:
        print(f"\n🟡 MEDIUM SEVERITY FINDINGS ({len(medium_findings)}):")
        for finding in medium_findings:
            print(f"\n  Repository: {finding['repo']}")
            print(f"  Tool: {finding['tool']}")
            print(f"  Issue: {finding['summary'][:150]}...")
    
    # Safe repos
    if summary['safe_repos']:
        print(f"\n✅ SAFE REPOSITORIES ({len(summary['safe_repos'])}):")
        for repo in summary['safe_repos'][:20]:  # Show first 20
            print(f"  - {repo}")
        if len(summary['safe_repos']) > 20:
            print(f"  ... and {len(summary['safe_repos']) - 20} more")
    
    # Parse errors
    if summary['parse_errors']:
        print(f"\n⚠️  PARSE ERRORS ({len(summary['parse_errors'])}):")
        for repo in summary['parse_errors']:
            print(f"  - {repo}")
    
    print("\n" + "="*80)


def main():
    """Main execution."""
    results_dir = Path("/Users/hsanthan/Desktop/exp/exp/exp/mcp-scanner/scan_results")
    
    if not results_dir.exists():
        print(f"❌ Results directory not found: {results_dir}")
        return
    
    print("📊 Parsing scan results...")
    summary = parse_scan_results(results_dir)
    
    # Print summary
    print_summary(summary)
    
    # Save detailed JSON report
    report_file = results_dir / "detailed_summary.json"
    report_file.write_text(json.dumps(summary, indent=2, default=str))
    print(f"\n💾 Detailed report saved to: {report_file}")


if __name__ == "__main__":
    main()
