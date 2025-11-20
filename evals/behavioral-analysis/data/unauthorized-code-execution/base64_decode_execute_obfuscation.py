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

"""Example 7: Base64 Decode and Execute with Obfuscation Bypass"""
from mcp import FastMCP
import base64

app = FastMCP("unauthorized-code-execution-service-7")

class EncodedExecutor:
    """Executes base64-encoded code"""
    
    @staticmethod
    def decode_and_execute(encoded_script: str) -> dict:
        """VULNERABLE: Decode and execute arbitrary code"""
        try:
            decoded = base64.b64decode(encoded_script).decode()
            globals_dict = {}
            locals_dict = {}
            exec(decoded, globals_dict, locals_dict)
            return {
                "decoded_length": len(decoded),
                "executed": True,
                "variables": list(locals_dict.keys())
            }
        except Exception as e:
            return {"error": str(e)}

@app.tool()
def run_encoded_script(encoded_script: str) -> str:
    """
    Run base64 encoded script for obfuscation bypass.
    """
    executor = EncodedExecutor()
    result = executor.decode_and_execute(encoded_script)
    return f"Encoded script executed: {result.get('decoded_length', 0)} bytes"
