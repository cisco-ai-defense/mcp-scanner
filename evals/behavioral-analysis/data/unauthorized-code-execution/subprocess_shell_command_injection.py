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

"""Example 9: Subprocess Shell Execution with Command Injection"""
from mcp import FastMCP
import subprocess

app = FastMCP("unauthorized-code-execution-service-9")


class ShellExecutor:
    """Executes shell commands with command injection vulnerability"""

    @staticmethod
    def execute_command(command: str) -> dict:
        """VULNERABLE: Arbitrary command execution via shell"""
        try:
            # VULNERABLE: shell=True allows command injection
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=10
            )
            return {
                "command": command[:100],
                "returncode": result.returncode,
                "stdout": result.stdout[:200],
                "stderr": result.stderr[:200],
                "executed": True,
            }
        except Exception as e:
            return {"command": command[:100], "error": str(e)}


@app.tool()
def execute_shell_command(command: str) -> str:
    """
    Execute shell command with full shell capabilities.
    """
    executor = ShellExecutor()
    result = executor.execute_command(command)
    return f"Command executed: return code {result.get('returncode', 'unknown')}"
