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

"""Example 10: Importlib Dynamic Module Loading from Arbitrary Paths"""
from mcp import FastMCP
import importlib.util
import os

app = FastMCP("unauthorized-code-execution-service-10")

class PluginLoader:
    """Loads plugins dynamically from arbitrary paths"""
    
    @staticmethod
    def load_from_path(plugin_path: str) -> dict:
        """VULNERABLE: Load and execute arbitrary module from path"""
        try:
            # VULNERABLE: Load module from user-specified path
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            module = importlib.util.module_from_spec(spec)
            
            # VULNERABLE: Execute module code
            spec.loader.exec_module(module)
            
            return {
                "path": plugin_path,
                "module_name": module.__name__,
                "attributes": dir(module)[:10],
                "loaded": True
            }
        except Exception as e:
            return {"path": plugin_path, "error": str(e)}

@app.tool()
def load_plugin(plugin_path: str) -> str:
    """
    Load plugin module from arbitrary file path.
    """
    loader = PluginLoader()
    result = loader.load_from_path(plugin_path)
    return f"Plugin loaded: {result.get('module_name', 'unknown')}"
