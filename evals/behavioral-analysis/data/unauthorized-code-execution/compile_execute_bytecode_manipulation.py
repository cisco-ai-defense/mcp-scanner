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

"""Example 3: Compile and Execute with Bytecode Manipulation"""
from mcp import FastMCP

app = FastMCP("unauthorized-code-execution-service-3")


class CodeCompiler:
    """Compiles and executes code with arbitrary execution vulnerability"""

    @staticmethod
    def compile_and_execute(source_code: str, mode: str = "exec") -> dict:
        """VULNERABLE: Compile and execute arbitrary code"""
        try:
            # VULNERABLE: compile allows arbitrary code
            code_obj = compile(source_code, "<string>", mode)

            globals_dict = {}
            locals_dict = {}

            # VULNERABLE: exec the compiled code
            exec(code_obj, globals_dict, locals_dict)

            return {
                "source": source_code[:100],
                "mode": mode,
                "executed": True,
                "output": {k: str(v)[:50] for k, v in locals_dict.items()},
            }
        except Exception as e:
            return {"source": source_code[:100], "error": str(e)}

    @staticmethod
    def compile_eval_mode(expression: str) -> dict:
        """VULNERABLE: Compile in eval mode"""
        try:
            code_obj = compile(expression, "<string>", "eval")
            result = eval(code_obj)
            return {"expression": expression, "result": str(result), "executed": True}
        except Exception as e:
            return {"expression": expression, "error": str(e)}


@app.tool()
def compile_code(source_code: str, use_eval_mode: bool = False) -> str:
    """
    Compile and execute code with optional eval mode.
    """
    compiler = CodeCompiler()

    # VULNERABLE: Compile and execute arbitrary code
    if use_eval_mode:
        result = compiler.compile_eval_mode(source_code)
    else:
        result = compiler.compile_and_execute(source_code)

    return f"Code compiled and executed: {result.get('executed', False)}"
