"""Example 5: Complex String Template Injection with Config Generation"""
from mcp import FastMCP
from string import Template
import os
import sys

app = FastMCP("template-injection-service-5")

class ConfigGenerator:
    """Generates configuration files using string templates"""
    
    CONFIG_TEMPLATES = {
        "server": Template("server_name=$server\nport=$port\nhost=$host"),
        "database": Template("db_host=$db_host\ndb_name=$db_name\ndb_user=$db_user"),
        "custom": Template("$config_content")
    }
    
    @staticmethod
    def build_template(template_type: str, custom_template: str = None) -> Template:
        """Build template from type or custom string"""
        if custom_template:
            # VULNERABLE: User-controlled template string
            return Template(custom_template)
        
        return ConfigGenerator.CONFIG_TEMPLATES.get(
            template_type,
            ConfigGenerator.CONFIG_TEMPLATES["custom"]
        )
    
    @staticmethod
    def build_context(base_values: dict, include_modules: bool = False) -> dict:
        """Build substitution context"""
        context = base_values.copy()
        
        if include_modules:
            # VULNERABLE: Including dangerous modules in context
            context.update({
                "os": os,
                "sys": sys,
                "__builtins__": __builtins__
            })
        
        return context
    
    @staticmethod
    def substitute_template(template: Template, context: dict,
                          use_safe: bool = True) -> str:
        """Substitute template variables"""
        if use_safe:
            # VULNERABLE: safe_substitute still allows access to context objects
            return template.safe_substitute(**context)
        else:
            # VULNERABLE: substitute requires all variables
            return template.substitute(**context)

@app.tool()
def generate_config(config_type: str = "server",
                   custom_template: str = "",
                   config_values: str = "",
                   include_system_vars: bool = False,
                   use_safe_mode: bool = True) -> str:
    """
    Generate configuration file from template with flexible substitution.
    """
    generator = ConfigGenerator()
    
    # Build template
    template = generator.build_template(config_type, custom_template)
    
    # Parse config values
    values = {
        "server": "localhost",
        "port": "8080",
        "host": "0.0.0.0",
        "db_host": "localhost",
        "db_name": "mydb",
        "db_user": "admin",
        "config_content": "default_config"
    }
    
    if config_values:
        try:
            import json
            custom_values = json.loads(config_values)
            values.update(custom_values)
        except:
            pass
    
    # VULNERABLE: Template injection through context objects
    # User can inject template: "$os.system('malicious')" with include_system_vars=True
    # Or: "${__builtins__.__import__('os').system('evil')}"
    # Or custom_template: "$sys.exit()" to crash the service
    
    # Build context
    context = generator.build_context(values, include_system_vars)
    
    # Substitute template
    result = generator.substitute_template(template, context, use_safe_mode)
    
    return f"Configuration generated:\n{result}"
