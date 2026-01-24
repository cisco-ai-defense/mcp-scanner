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

"""Example 8: Complex Cheetah Template Injection with Search Lists"""
from mcp import FastMCP

app = FastMCP("template-injection-service-8")


class CheetahDocumentGenerator:
    """Generates documents using Cheetah templates"""

    @staticmethod
    def build_search_list(base_context: dict, additional_contexts: list = None) -> list:
        """Build Cheetah search list"""
        search_list = [base_context]

        if additional_contexts:
            # VULNERABLE: Adding user-controlled contexts
            search_list.extend(additional_contexts)

        return search_list

    @staticmethod
    def render_template(
        template_source: str, search_list: list, enable_caching: bool = False
    ) -> str:
        """Render Cheetah template"""
        from Cheetah.Template import Template

        # VULNERABLE: User-controlled template source
        template = Template(
            template_source,
            searchList=search_list,
            compilerSettings={"useLegacyImportMode": False},
        )

        return str(template)

    @staticmethod
    def render_with_directives(
        template_source: str, context: dict, custom_directives: str = None
    ) -> str:
        """Render with custom directives"""
        from Cheetah.Template import Template

        if custom_directives:
            # VULNERABLE: Prepending custom directives
            template_source = f"{custom_directives}\n{template_source}"

        template = Template(template_source, searchList=[context])
        return str(template)


@app.tool()
def generate_document(
    template_source: str,
    context_json: str = "{}",
    additional_contexts: str = "",
    custom_directives: str = "",
    enable_imports: bool = False,
) -> str:
    """
    Generate document from Cheetah template with flexible context.
    """
    generator = CheetahDocumentGenerator()

    # Parse context
    import json

    try:
        context = json.loads(context_json)
    except:
        context = {"content": context_json}

    # Parse additional contexts
    extra_contexts = []
    if additional_contexts:
        try:
            extra_contexts = json.loads(additional_contexts)
            if not isinstance(extra_contexts, list):
                extra_contexts = [extra_contexts]
        except:
            pass

    # VULNERABLE: Cheetah SSTI allows Python code execution
    # User can inject: "#import os\n$os.system('malicious')"
    # Or: "#from subprocess import call\n$call(['sh', '-c', 'evil'])"
    # Or: "$__import__('os').system('command')"

    # Build search list
    search_list = generator.build_search_list(context, extra_contexts)

    # Render template
    if custom_directives:
        result = generator.render_with_directives(
            template_source, context, custom_directives
        )
    else:
        result = generator.render_template(template_source, search_list)

    return f"Document generated:\n{result[:500]}..."
