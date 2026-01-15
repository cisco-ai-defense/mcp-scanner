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

"""Example 9: Complex Django Template Injection with Custom Tags"""
from mcp import FastMCP
from django.template import Template, Context, Engine
from django.conf import settings

app = FastMCP("template-injection-service-9")


class DjangoTemplateRenderer:
    """Renders Django templates with custom configuration"""

    def __init__(self):
        if not settings.configured:
            settings.configure(
                DEBUG=True,
                TEMPLATES=[
                    {
                        "BACKEND": "django.template.backends.django.DjangoTemplates",
                        "OPTIONS": {
                            "context_processors": [],
                        },
                    }
                ],
            )
        self.engine = Engine.get_default()

    def render_template(
        self, template_string: str, context_data: dict, autoescape: bool = True
    ) -> str:
        """Render Django template"""
        # VULNERABLE: User-controlled template string
        template = Template(template_string)
        context = Context(context_data, autoescape=autoescape)
        return template.render(context)

    def render_with_custom_tags(
        self, template_string: str, context_data: dict, custom_tags: str = None
    ) -> str:
        """Render with custom template tags"""
        if custom_tags:
            # VULNERABLE: Loading custom template tags
            template_string = f"{{% load {custom_tags} %}}\n{template_string}"

        template = Template(template_string)
        context = Context(context_data)
        return template.render(context)

    def render_from_string(self, template_string: str, context_data: dict) -> str:
        """Render using engine's from_string method"""
        # VULNERABLE: Another injection point
        template = self.engine.from_string(template_string)
        return template.render(context_data)


@app.tool()
def render_django_template(
    template_string: str,
    context_json: str = "{}",
    custom_tags: str = "",
    disable_autoescape: bool = False,
    use_engine: bool = False,
) -> str:
    """
    Render Django template with context and custom tags.
    """
    renderer = DjangoTemplateRenderer()

    # Parse context
    import json

    try:
        context_data = json.loads(context_json)
    except:
        context_data = {"content": context_json}

    # VULNERABLE: Django SSTI with template tags
    # User can inject: "{{ settings.SECRET_KEY }}"
    # Or: "{% load static %}{% get_static_prefix %}"
    # Or: "{% debug %}" to expose debug information
    # Or: "{{ request.META }}" if request in context

    try:
        if custom_tags:
            result = renderer.render_with_custom_tags(
                template_string, context_data, custom_tags
            )
        elif use_engine:
            result = renderer.render_from_string(template_string, context_data)
        else:
            result = renderer.render_template(
                template_string, context_data, not disable_autoescape
            )

        return f"Template rendered:\n{result[:500]}..."
    except Exception as e:
        return f"Render error: {str(e)}"
