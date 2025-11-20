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

"""Example 3: Complex F-string Injection with Dynamic Evaluation"""
from mcp import FastMCP

app = FastMCP("template-injection-service-3")

class MessageFormatter:
    """Formats messages using f-string evaluation"""
    
    @staticmethod
    def build_context(variables: dict, include_builtins: bool = False) -> dict:
        """Build evaluation context"""
        context = variables.copy()
        
        if include_builtins:
            # VULNERABLE: Including builtins in context
            context["__builtins__"] = __builtins__
        
        return context
    
    @staticmethod
    def format_with_fstring(template: str, context: dict) -> str:
        """Format string using f-string evaluation"""
        # VULNERABLE: eval with f-string allows arbitrary code execution
        try:
            result = eval(f'f"{template}"', context)
            return str(result)
        except Exception as e:
            return f"Format error: {str(e)}"
    
    @staticmethod
    def format_with_expressions(template: str, expressions: dict) -> str:
        """Format with pre-evaluated expressions"""
        context = {}
        
        for key, expr in expressions.items():
            try:
                # VULNERABLE: Evaluating user expressions
                context[key] = eval(expr)
            except:
                context[key] = expr
        
        return eval(f'f"{template}"', context)

@app.tool()
def format_message(template: str,
                  name: str = "",
                  custom_vars: str = "",
                  enable_expressions: bool = False,
                  include_builtins: bool = False) -> str:
    """
    Format message with user variables and dynamic expressions.
    """
    formatter = MessageFormatter()
    
    # Build base context
    context = {
        "name": name,
        "user": name,
        "greeting": "Hello"
    }
    
    # Parse custom variables
    if custom_vars:
        try:
            import json
            custom_dict = json.loads(custom_vars)
            context.update(custom_dict)
        except:
            pass
    
    # VULNERABLE: F-string injection through eval
    # User can inject: "{__import__('os').system('malicious')}"
    # Or: "{().__class__.__bases__[0].__subclasses__()}"
    # Or: "{open('/etc/passwd').read()}"
    
    if enable_expressions and custom_vars:
        # VULNERABLE: Evaluating custom expressions
        try:
            expressions = json.loads(custom_vars)
            result = formatter.format_with_expressions(template, expressions)
        except:
            result = formatter.format_with_fstring(template, context)
    else:
        # Build context with optional builtins
        eval_context = formatter.build_context(context, include_builtins)
        result = formatter.format_with_fstring(template, eval_context)
    
    return f"Formatted message: {result}"
