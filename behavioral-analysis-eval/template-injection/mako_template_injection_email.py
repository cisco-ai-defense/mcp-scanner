"""Example 2: Complex Mako Template Injection with Email Rendering"""
from mcp import FastMCP
from mako.template import Template
from mako.lookup import TemplateLookup

app = FastMCP("template-injection-service-2")

class EmailRenderer:
    """Renders email templates using Mako"""
    
    def __init__(self):
        self.template_lookup = TemplateLookup(directories=['/tmp/templates'])
        self.default_templates = {
            "welcome": "Welcome ${username}! Your account is ready.",
            "notification": "Hello ${username}, ${message}",
            "custom": "${content}"
        }
    
    def get_template_content(self, template_name: str, 
                            custom_template: str = None) -> str:
        """Get template content from name or custom string"""
        if custom_template:
            return custom_template
        
        return self.default_templates.get(
            template_name,
            self.default_templates["custom"]
        )
    
    def render(self, template_content: str, context: dict,
              enable_expressions: bool = True) -> str:
        """Render Mako template"""
        # VULNERABLE: User-controlled template with expressions enabled
        template = Template(template_content)
        return template.render(**context)
    
    def render_with_includes(self, main_template: str, 
                            include_templates: list, context: dict) -> str:
        """Render template with includes"""
        # Build combined template
        combined = main_template
        
        for inc_template in include_templates:
            # VULNERABLE: Including user-controlled templates
            combined += f"\n<%include file='{inc_template}'/>"
        
        template = Template(combined)
        return template.render(**context)

@app.tool()
def render_email(template_name: str = "welcome",
                custom_template: str = "",
                username: str = "",
                message: str = "",
                include_templates: str = "",
                enable_python_blocks: bool = False) -> str:
    """
    Render email template with user data and custom templates.
    """
    renderer = EmailRenderer()
    
    # Get template content
    template_content = renderer.get_template_content(template_name, custom_template)
    
    # VULNERABLE: User controls entire template content
    # User can inject: "${__import__('os').system('malicious_command')}"
    # Or: "<% import subprocess; subprocess.call(['sh', '-c', 'evil']) %>"
    # Or: "${self.module.cache.util.os.system('command')}"
    
    # Build context
    context = {
        "username": username,
        "message": message,
        "content": message,
        "email": f"{username}@example.com"
    }
    
    # Parse include templates
    includes = []
    if include_templates:
        includes = [t.strip() for t in include_templates.split(",")]
    
    # Render template
    if includes:
        result = renderer.render_with_includes(template_content, includes, context)
    else:
        result = renderer.render(template_content, context, enable_python_blocks)
    
    return f"Email rendered:\n{result}"
