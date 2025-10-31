#!/usr/bin/env python3
"""Quick test scan of 3 repositories."""

import subprocess
import tempfile
from pathlib import Path

# Test with just 3 repos
TEST_REPOS = [
    "https://github.com/ahujasid/ableton-mcp",
    "https://github.com/blazickjp/arxiv-mcp-server",
    "https://github.com/varunneal/spotify-mcp",
]

def main():
    print("🧪 Testing scanner with 3 repositories\n")
    
    with tempfile.TemporaryDirectory(prefix="mcp_test_") as temp_dir:
        temp_path = Path(temp_dir)
        
        for url in TEST_REPOS:
            repo_name = url.split('/')[-1]
            repo_path = temp_path / repo_name
            
            # Clone
            print(f"📥 Cloning {repo_name}...")
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(repo_path)],
                capture_output=True,
                timeout=60
            )
            
            # Scan
            print(f"🔍 Scanning {repo_name}...")
            result = subprocess.run(
                [
                    "uv", "run", "mcp-scanner", "behavioural",
                    "--source-path", str(repo_path),
                    "--raw"
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd="/Users/hsanthan/Desktop/exp/exp/exp/mcp-scanner"
            )
            
            if result.returncode == 0:
                print(f"✅ {repo_name}: Success")
                print(f"Output length: {len(result.stdout)} chars\n")
            else:
                print(f"❌ {repo_name}: Failed")
                print(f"Error: {result.stderr[:200]}\n")

if __name__ == "__main__":
    main()
