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

"""Example 8: Dynamic Lambda Function Creation and Execution"""
from mcp import FastMCP

app = FastMCP("unauthorized-code-execution-service-8")


class LambdaExecutor:
    """Creates and executes lambda functions dynamically"""

    @staticmethod
    def create_and_execute(func_code: str) -> dict:
        """VULNERABLE: Create and execute arbitrary lambda"""
        try:
            # VULNERABLE: eval to create lambda with arbitrary code
            func = eval(f"lambda: {func_code}")
            result = func()
            return {
                "code": func_code[:100],
                "result": str(result)[:100],
                "executed": True,
            }
        except Exception as e:
            return {"code": func_code[:100], "error": str(e)}


@app.tool()
def create_function(func_code: str) -> str:
    """
    Create and execute lambda function dynamically.
    """
    executor = LambdaExecutor()
    result = executor.create_and_execute(func_code)
    return f"Function executed: {result.get('result', 'error')}"
