#!/usr/bin/env python3
"""
Script to download and scan multiple MCP repositories.
Downloads repos to a temp directory and runs mcp-scanner on each.
"""

import subprocess
import tempfile
import shutil
from pathlib import Path
import json
import sys

# List of repositories to scan
REPOS = [
    "https://github.com/awslabs/mcp",
    "https://github.com/semgrep/mcp",
    "https://github.com/baidu-maps/mcp",
    "https://github.com/ahujasid/ableton-mcp",
    "https://github.com/crystaldba/postgres-mcp",
    "https://github.com/sparfenyuk/mcp-proxy",
    "https://github.com/elevenlabs/elevenlabs-mcp",
    "https://github.com/databrickslabs/mcp",
    "https://github.com/MariaDB/mcp",
    "https://github.com/designcomputer/mysql_mcp_server",
    "https://github.com/taylorwilsdon/google_workspace_mcp",
    "https://github.com/coleam00/mcp-mem0",
    "https://github.com/qdrant/mcp-server-qdrant",
    "https://github.com/blazickjp/arxiv-mcp-server",
    "https://github.com/MiniMax-AI/MiniMax-MCP",
    "https://github.com/firstbatchxyz/mem-agent-mcp",
    "https://github.com/langchain-ai/mcpdoc",
    "https://github.com/ckreiling/mcp-server-docker",
    "https://github.com/GH05TCREW/MetasploitMCP",
    "https://github.com/financial-datasets/mcp-server",
    "https://github.com/Operative-Sh/web-eval-agent",
    "https://github.com/rohitg00/kubectl-mcp-server",
    "https://github.com/tuanle96/mcp-odoo",
    "https://github.com/datalayer/jupyter-mcp-server",
    "https://github.com/cryxnet/DeepMCPAgent",
    "https://github.com/chigwell/telegram-mcp",
    "https://github.com/varunneal/spotify-mcp",
    "https://github.com/GongRzhe/Office-Word-MCP-Server",
    "https://github.com/Saik0s/mcp-browser-use",
    "https://github.com/saidsurucu/yargi-mcp",
    "https://github.com/svnscha/mcp-windbg",
    "https://github.com/xing5/mcp-google-sheets",
    "https://github.com/nickclyde/duckduckgo-mcp-server",
    "https://github.com/GongRzhe/Office-PowerPoint-MCP-Server",
    "https://github.com/stickerdaniel/linkedin-mcp-server",
    "https://github.com/chroma-core/chroma-mcp",
    "https://github.com/coleam00/supabase-mcp",
    "https://github.com/kontext-dev/browser-use-mcp-server",
    "https://github.com/54yyyu/zotero-mcp",
    "https://github.com/redis/mcp-redis",
    "https://github.com/alpacahq/alpaca-mcp-server",
    "https://github.com/azure-ai-foundry/mcp-foundry",
    "https://github.com/neka-nat/freecad-mcp",
    "https://github.com/vivekVells/mcp-pandoc",
    "https://github.com/pipeboard-co/meta-ads-mcp",
    "https://github.com/docling-project/docling-mcp",
    "https://github.com/apache/doris-mcp-server",
    "https://github.com/runekaagaard/mcp-alchemy",
    "https://github.com/minhalvp/android-mcp-server",
]


def get_repo_name(url: str) -> str:
    """Extract repository name from GitHub URL."""
    return url.rstrip('/').split('/')[-1]


def clone_repo(url: str, target_dir: Path) -> bool:
    """Clone a repository to target directory.
    
    Args:
        url: GitHub repository URL
        target_dir: Directory to clone into
        
    Returns:
        True if successful, False otherwise
    """
    repo_name = get_repo_name(url)
    repo_path = target_dir / repo_name
    
    print(f"\n📥 Cloning {repo_name}...")
    
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(repo_path)],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            print(f"✅ Cloned {repo_name}")
            return True
        else:
            print(f"❌ Failed to clone {repo_name}: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏱️  Timeout cloning {repo_name}")
        return False
    except Exception as e:
        print(f"❌ Error cloning {repo_name}: {e}")
        return False


def scan_repo(repo_path: Path, output_dir: Path) -> dict:
    """Run mcp-scanner on a repository.
    
    Args:
        repo_path: Path to repository
        output_dir: Directory for scan results
        
    Returns:
        Scan results dictionary
    """
    repo_name = repo_path.name
    output_file = output_dir / f"{repo_name}_scan.json"
    
    print(f"\n🔍 Scanning {repo_name}...")
    
    try:
        # Run behavioural analysis
        result = subprocess.run(
            [
                "uv", "run", "mcp-scanner", "behavioural",
                "--source-path", str(repo_path),
                "--raw"
            ],
            capture_output=True,
            text=True,
            timeout=300,
            cwd="/Users/hsanthan/Desktop/exp/exp/exp/mcp-scanner"
        )
        
        if result.returncode == 0:
            # Save results
            output_file.write_text(result.stdout)
            
            # Parse to get summary
            try:
                scan_data = json.loads(result.stdout)
                findings_count = len(scan_data.get("findings", []))
                print(f"✅ Scanned {repo_name}: {findings_count} finding(s)")
                
                return {
                    "repo": repo_name,
                    "status": "success",
                    "findings_count": findings_count,
                    "output_file": str(output_file)
                }
            except json.JSONDecodeError:
                print(f"⚠️  Scan completed but output not JSON: {repo_name}")
                return {
                    "repo": repo_name,
                    "status": "completed_non_json",
                    "output_file": str(output_file)
                }
        else:
            print(f"❌ Scan failed for {repo_name}: {result.stderr[:200]}")
            return {
                "repo": repo_name,
                "status": "failed",
                "error": result.stderr[:500]
            }
            
    except subprocess.TimeoutExpired:
        print(f"⏱️  Scan timeout for {repo_name}")
        return {
            "repo": repo_name,
            "status": "timeout"
        }
    except Exception as e:
        print(f"❌ Error scanning {repo_name}: {e}")
        return {
            "repo": repo_name,
            "status": "error",
            "error": str(e)
        }


def main():
    """Main execution function."""
    print("🚀 MCP Repository Scanner")
    print(f"📊 Total repositories to scan: {len(REPOS)}")
    
    # Create temp directory for cloning
    with tempfile.TemporaryDirectory(prefix="mcp_scan_") as temp_dir:
        temp_path = Path(temp_dir)
        print(f"\n📁 Using temp directory: {temp_path}")
        
        # Create output directory for results
        output_dir = Path("/Users/hsanthan/Desktop/exp/exp/exp/mcp-scanner/scan_results")
        output_dir.mkdir(exist_ok=True)
        print(f"📁 Results will be saved to: {output_dir}")
        
        results = []
        cloned_repos = []
        
        # Clone all repositories
        print("\n" + "="*60)
        print("PHASE 1: CLONING REPOSITORIES")
        print("="*60)
        
        for url in REPOS:
            if clone_repo(url, temp_path):
                repo_name = get_repo_name(url)
                cloned_repos.append(temp_path / repo_name)
        
        print(f"\n✅ Successfully cloned {len(cloned_repos)}/{len(REPOS)} repositories")
        
        # Scan all cloned repositories
        print("\n" + "="*60)
        print("PHASE 2: SCANNING REPOSITORIES")
        print("="*60)
        
        for repo_path in cloned_repos:
            result = scan_repo(repo_path, output_dir)
            results.append(result)
        
        # Generate summary report
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        
        successful_scans = [r for r in results if r["status"] == "success"]
        failed_scans = [r for r in results if r["status"] == "failed"]
        timeout_scans = [r for r in results if r["status"] == "timeout"]
        
        print(f"\n✅ Successful scans: {len(successful_scans)}")
        print(f"❌ Failed scans: {len(failed_scans)}")
        print(f"⏱️  Timeout scans: {len(timeout_scans)}")
        
        # Show repos with findings
        repos_with_findings = [r for r in successful_scans if r.get("findings_count", 0) > 0]
        if repos_with_findings:
            print(f"\n🚨 Repositories with security findings: {len(repos_with_findings)}")
            for r in sorted(repos_with_findings, key=lambda x: x["findings_count"], reverse=True):
                print(f"  - {r['repo']}: {r['findings_count']} finding(s)")
        
        # Save summary
        summary_file = output_dir / "scan_summary.json"
        summary_file.write_text(json.dumps({
            "total_repos": len(REPOS),
            "cloned": len(cloned_repos),
            "scanned": len(results),
            "successful": len(successful_scans),
            "failed": len(failed_scans),
            "timeout": len(timeout_scans),
            "repos_with_findings": len(repos_with_findings),
            "results": results
        }, indent=2))
        
        print(f"\n📄 Summary saved to: {summary_file}")
        print(f"\n✨ Scan complete! Check {output_dir} for detailed results.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        sys.exit(1)
