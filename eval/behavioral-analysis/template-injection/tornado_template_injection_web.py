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

"""Example 4: Complex Tornado Template Injection with Web Page Rendering"""
from mcp import FastMCP
from tornado.template import Template, Loader
import os

app = FastMCP("template-injection-service-4")

class WebPageRenderer:
    """Renders web pages using Tornado templates"""
    
    def __init__(self):
        self.template_dir = "/tmp/templates"
        self.loader = None
    
    def init_loader(self):
        """Initialize template loader"""
        if os.path.exists(self.template_dir):
            self.loader = Loader(self.template_dir)
    
    def build_page_template(self, layout: str, content_blocks: list) -> str:
        """Build page template from layout and blocks"""
        template_parts = [layout]
        
        for block in content_blocks:
            # VULNERABLE: User-controlled template blocks
            template_parts.append(block)
        
        return "\n".join(template_parts)
    
    def render_template(self, template_str: str, context: dict,
                       enable_autoescape: bool = True) -> bytes:
        """Render Tornado template"""
        # VULNERABLE: User-controlled template string
        template = Template(template_str, autoescape="xhtml_escape" if enable_autoescape else None)
        return template.generate(**context)
    
    def render_with_modules(self, template_str: str, context: dict,
                           module_code: str = None) -> bytes:
        """Render template with custom module code"""
        if module_code:
            # VULNERABLE: Injecting module code into template
            template_str = f"{{% module {module_code} %}}\n{template_str}"
        
        template = Template(template_str)
        return template.generate(**context)

@app.tool()
def render_page(page_template: str,
               content: str = "",
               layout: str = "default",
               custom_blocks: str = "",
               module_code: str = "",
               disable_autoescape: bool = False) -> str:
    """
    Render web page with dynamic content and custom template blocks.
    """
    renderer = WebPageRenderer()
    
    # Parse custom blocks
    blocks = []
    if custom_blocks:
        blocks = [b.strip() for b in custom_blocks.split("|||")]
    
    # Build template
    if blocks:
        template_str = renderer.build_page_template(page_template, blocks)
    else:
        template_str = page_template
    
    # VULNERABLE: Tornado SSTI allows Python code execution
    # User can inject: "{% import os %}{{ os.system('malicious') }}"
    # Or: "{{ __import__('subprocess').call(['sh', '-c', 'evil']) }}"
    # Or: "{% raw exec('malicious_code') %}"
    
    # Build context
    context = {
        "content": content,
        "title": "Page Title",
        "layout": layout,
        "user": "guest"
    }
    
    # Render template
    if module_code:
        result = renderer.render_with_modules(template_str, context, module_code)
    else:
        result = renderer.render_template(template_str, context, not disable_autoescape)
    
    return f"Page rendered: {len(result)} bytes"
