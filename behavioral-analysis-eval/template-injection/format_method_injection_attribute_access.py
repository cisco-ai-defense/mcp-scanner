"""Example 7: Complex Format Method Injection with Attribute Access"""
from mcp import FastMCP

app = FastMCP("template-injection-service-7")

class StringFormatter:
    """Formats strings using format() method"""
    
    @staticmethod
    def format_simple(format_str: str, values: dict) -> str:
        """Simple format with dictionary unpacking"""
        # VULNERABLE: format() can access object attributes
        return format_str.format(**values)
    
    @staticmethod
    def format_with_positional(format_str: str, *args) -> str:
        """Format with positional arguments"""
        # VULNERABLE: Positional format injection
        return format_str.format(*args)
    
    @staticmethod
    def format_with_objects(format_str: str, objects: dict) -> str:
        """Format with object access"""
        # VULNERABLE: Can access object methods and attributes
        return format_str.format_map(objects)
    
    @staticmethod
    def build_format_context(base_values: dict, 
                            include_objects: bool = False) -> dict:
        """Build formatting context"""
        context = base_values.copy()
        
        if include_objects:
            # VULNERABLE: Including objects in context
            context.update({
                "list": [],
                "dict": {},
                "str": "",
                "int": 0
            })
        
        return context

@app.tool()
def format_string(format_str: str,
                 values_json: str = "{}",
                 positional_args: str = "",
                 include_builtins: bool = False,
                 use_format_map: bool = False) -> str:
    """
    Format string with provided values and flexible formatting options.
    """
    formatter = StringFormatter()
    
    # Parse values
    import json
    try:
        values = json.loads(values_json)
    except:
        values = {"value": values_json}
    
    # Build context
    context = formatter.build_format_context(values, include_builtins)
    
    # Parse positional args
    args = []
    if positional_args:
        args = [arg.strip() for arg in positional_args.split(",")]
    
    # VULNERABLE: Format string injection
    # User can inject: "{0.__class__.__bases__[0].__subclasses__()}"
    # Or: "{list.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules}"
    # Or: "{dict.__class__.__mro__[1].__subclasses__()}"
    
    try:
        if args:
            result = formatter.format_with_positional(format_str, *args)
        elif use_format_map:
            result = formatter.format_with_objects(format_str, context)
        else:
            result = formatter.format_simple(format_str, context)
        
        return f"Formatted string: {result}"
    except Exception as e:
        return f"Format error: {str(e)}"
