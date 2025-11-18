"""Example 6: Complex Jinja2 with Autoescape Disabled and Filters"""
from mcp import FastMCP
from jinja2 import Environment, select_autoescape

app = FastMCP("template-injection-service-6")

class HTMLRenderer:
    """Renders HTML using Jinja2 with configurable autoescape"""
    
    def __init__(self, autoescape: bool = True):
        if autoescape:
            self.env = Environment(
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            # VULNERABLE: Autoescape disabled
            self.env = Environment(autoescape=False)
    
    def add_custom_filters(self, filters: dict):
        """Add custom Jinja2 filters"""
        for name, func in filters.items():
            # VULNERABLE: User-defined filters
            self.env.filters[name] = func
    
    def render(self, template_str: str, context: dict,
              enable_extensions: bool = False) -> str:
        """Render template with context"""
        if enable_extensions:
            # VULNERABLE: Enable Jinja2 extensions
            self.env.add_extension('jinja2.ext.do')
            self.env.add_extension('jinja2.ext.loopcontrols')
        
        # VULNERABLE: User-controlled template
        template = self.env.from_string(template_str)
        return template.render(**context)

@app.tool()
def render_html(html_template: str,
               data_json: str = "{}",
               disable_autoescape: bool = False,
               custom_filters: str = "",
               enable_extensions: bool = False) -> str:
    """
    Render HTML content from template with custom filters and extensions.
    """
    # Initialize renderer
    renderer = HTMLRenderer(autoescape=not disable_autoescape)
    
    # Parse data
    import json
    try:
        data = json.loads(data_json)
    except:
        data = {"content": data_json}
    
    # Add custom filters if provided
    if custom_filters:
        # VULNERABLE: Eval custom filter functions
        try:
            filters_dict = eval(custom_filters)
            if isinstance(filters_dict, dict):
                renderer.add_custom_filters(filters_dict)
        except:
            pass
    
    # VULNERABLE: SSTI with autoescape disabled
    # User can inject: "{{ config.items() }}" to access config
    # Or: "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}"
    # Or: "{% for c in [].__class__.__base__.__subclasses__() %}{{ c }}{% endfor %}"
    
    result = renderer.render(html_template, data, enable_extensions)
    
    return f"HTML rendered:\n{result[:500]}..."
