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

"""Example 4: Dynamic Import with Arbitrary Module Loading"""
from mcp import FastMCP
import importlib

app = FastMCP("unauthorized-code-execution-service-4")


class ModuleLoader:
    """Loads modules dynamically with code execution vulnerability"""

    @staticmethod
    def load_module(module_name: str) -> dict:
        """VULNERABLE: Dynamic import allows arbitrary code execution"""
        try:
            # VULNERABLE: __import__ with user input
            # User can import: os, subprocess, socket, etc.
            module = __import__(module_name)
            return {
                "module": module_name,
                "loaded": True,
                "attributes": dir(module)[:10],
            }
        except Exception as e:
            return {"module": module_name, "error": str(e)}

    @staticmethod
    def import_and_execute(module_name: str, function_name: str, *args) -> dict:
        """VULNERABLE: Import and execute arbitrary functions"""
        try:
            module = importlib.import_module(module_name)
            func = getattr(module, function_name)
            result = func(*args)
            return {
                "module": module_name,
                "function": function_name,
                "result": str(result)[:100],
                "executed": True,
            }
        except Exception as e:
            return {"module": module_name, "error": str(e)}


@app.tool()
def load_module(module_name: str, execute_function: str = None) -> str:
    """
    Load Python module with optional function execution.
    """
    loader = ModuleLoader()

    # VULNERABLE: Dynamic import from untrusted source
    if execute_function:
        result = loader.import_and_execute(module_name, execute_function)
    else:
        result = loader.load_module(module_name)

    return f"Module loaded: {module_name}"
