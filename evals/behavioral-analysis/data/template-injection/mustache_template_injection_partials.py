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

"""Example 10: Complex Mustache Template Injection with Partials"""
from mcp import FastMCP
import pystache

app = FastMCP("template-injection-service-10")

class MustacheRenderer:
    """Renders Mustache templates with partials and lambdas"""
    
    def __init__(self):
        self.renderer = pystache.Renderer()
        self.partials = {}
    
    def add_partial(self, name: str, content: str):
        """Add partial template"""
        # VULNERABLE: User-controlled partials
        self.partials[name] = content
    
    def render(self, template: str, context: dict,
              enable_lambdas: bool = False) -> str:
        """Render Mustache template"""
        if enable_lambdas and 'lambdas' in context:
            # VULNERABLE: User-defined lambda functions
            for key, func_str in context.get('lambdas', {}).items():
                try:
                    context[key] = eval(f"lambda text: {func_str}")
                except:
                    pass
        
        # Set partials
        self.renderer.partials = self.partials
        
        # VULNERABLE: User-controlled template
        return self.renderer.render(template, context)
    
    def render_with_partials(self, template: str, context: dict,
                            partial_templates: dict) -> str:
        """Render with multiple partials"""
        for name, content in partial_templates.items():
            self.add_partial(name, content)
        
        return self.render(template, context)

@app.tool()
def render_mustache(mustache_template: str,
                   data_json: str = "{}",
                   partials_json: str = "{}",
                   enable_lambdas: bool = False,
                   lambda_functions: str = "") -> str:
    """
    Render Mustache template with data, partials, and lambda functions.
    """
    renderer = MustacheRenderer()
    
    # Parse data
    import json
    try:
        template_data = json.loads(data_json)
    except:
        template_data = {"content": data_json}
    
    # Parse partials
    partials = {}
    if partials_json:
        try:
            partials = json.loads(partials_json)
        except:
            pass
    
    # Parse lambda functions
    if enable_lambdas and lambda_functions:
        try:
            lambdas = json.loads(lambda_functions)
            template_data['lambdas'] = lambdas
        except:
            pass
    
    # VULNERABLE: Mustache with lambdas allows code execution
    # User can inject lambda: "lambda text: __import__('os').system('malicious')"
    # Or partial with malicious content
    # Or: "{{#lambda}}{{name}}{{/lambda}}" with lambda that executes code
    
    if partials:
        result = renderer.render_with_partials(
            mustache_template, template_data, partials
        )
    else:
        result = renderer.render(mustache_template, template_data, enable_lambdas)
    
    return f"Mustache rendered:\n{result[:500]}..."
