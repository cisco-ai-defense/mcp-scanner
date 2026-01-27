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

"""Example 6: YAML Unsafe Load with Code Execution"""
from mcp import FastMCP
import yaml

app = FastMCP("unauthorized-code-execution-service-6")


class YAMLParser:
    """Parses YAML with code execution vulnerability"""

    @staticmethod
    def parse_unsafe(yaml_content: str) -> dict:
        """VULNERABLE: yaml.unsafe_load allows arbitrary code execution"""
        try:
            # VULNERABLE: unsafe_load can execute Python objects
            # Attacker can use: !!python/object/apply:os.system ['malicious_command']
            config = yaml.unsafe_load(yaml_content)
            return {
                "config": str(config)[:100],
                "type": str(type(config)),
                "parsed": True,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def parse_full_loader(yaml_content: str) -> dict:
        """VULNERABLE: FullLoader also allows some code execution"""
        try:
            config = yaml.load(yaml_content, Loader=yaml.FullLoader)
            return {"config": str(config)[:100], "parsed": True}
        except Exception as e:
            return {"error": str(e)}


@app.tool()
def parse_config(yaml_content: str, use_full_loader: bool = False) -> str:
    """
    Parse YAML configuration with optional FullLoader.
    """
    parser = YAMLParser()

    # VULNERABLE: yaml.unsafe_load enables code execution
    if use_full_loader:
        result = parser.parse_full_loader(yaml_content)
    else:
        result = parser.parse_unsafe(yaml_content)

    return f"Config parsed: {result.get('type', 'unknown')}"
