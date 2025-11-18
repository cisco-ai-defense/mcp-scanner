"""Example 1: Complex Jinja2 SSTI with Dynamic Template Construction"""
from mcp import FastMCP
from jinja2 import Template, Environment

app = FastMCP("template-injection-service-1")

class ReportGenerator:
    """Generates reports using Jinja2 templates"""
    
    REPORT_TEMPLATES = {
        "user_activity": "User: {{ username }} - Activity: {{ activity }}",
        "system_status": "System: {{ system_name }} - Status: {{ status }}",
        "custom": "{{ content }}"
    }
    
    @staticmethod
    def build_template(template_type: str, custom_sections: list = None) -> str:
        """Build template string with custom sections"""
        base_template = ReportGenerator.REPORT_TEMPLATES.get(
            template_type, 
            ReportGenerator.REPORT_TEMPLATES["custom"]
        )
        
        if custom_sections:
            # VULNERABLE: Concatenating user input into template
            for section in custom_sections:
                base_template += f"\n{section}"
        
        return base_template
    
    @staticmethod
    def render_template(template_str: str, context: dict) -> str:
        """Render Jinja2 template with context"""
        # VULNERABLE: User-controlled template string
        template = Template(template_str)
        return template.render(**context)

@app.tool()
def generate_report(username: str,
                   activity_data: str,
                   template_type: str = "user_activity",
                   custom_format: str = "",
                   include_timestamp: bool = True) -> str:
    """
    Generate formatted user activity report with custom templates.
    """
    generator = ReportGenerator()
    
    # Build custom sections
    custom_sections = []
    
    if custom_format:
        # VULNERABLE: User-provided format string added to template
        custom_sections.append(custom_format)
    
    if include_timestamp:
        custom_sections.append("Timestamp: {{ timestamp }}")
    
    # VULNERABLE: Template construction with user input
    # User can inject: "{{ ''.__class__.__mro__[1].__subclasses__() }}" to access Python internals
    # Or: "{% for item in [].__class__.__base__.__subclasses__() %}{{ item }}{% endfor %}"
    template_str = generator.build_template(template_type, custom_sections)
    
    # Build context
    context = {
        "username": username,
        "activity": activity_data,
        "system_name": "MCP Server",
        "status": "Active",
        "content": activity_data,
        "timestamp": "2024-01-01 12:00:00"
    }
    
    # VULNERABLE: Render user-controlled template
    result = generator.render_template(template_str, context)
    
    return f"Report generated:\n{result}"
