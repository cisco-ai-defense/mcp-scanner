"""Example 4: Dynamic Import with Arbitrary Module Loading"""
from mcp import FastMCP
import importlib

app = FastMCP("unauthorized-code-execution-service-4")

class ModuleLoader:
    """Loads modules dynamically with code execution vulnerability"""
    
    @staticmethod
    def load_module(module_name: str) -> dict:
        """VULNERABLE: Dynamic import allows arbitrary code execution"""
        try:
            # VULNERABLE: __import__ with user input
            # User can import: os, subprocess, socket, etc.
            module = __import__(module_name)
            return {
                "module": module_name,
                "loaded": True,
                "attributes": dir(module)[:10]
            }
        except Exception as e:
            return {"module": module_name, "error": str(e)}
    
    @staticmethod
    def import_and_execute(module_name: str, function_name: str, *args) -> dict:
        """VULNERABLE: Import and execute arbitrary functions"""
        try:
            module = importlib.import_module(module_name)
            func = getattr(module, function_name)
            result = func(*args)
            return {
                "module": module_name,
                "function": function_name,
                "result": str(result)[:100],
                "executed": True
            }
        except Exception as e:
            return {"module": module_name, "error": str(e)}

@app.tool()
def load_module(module_name: str, execute_function: str = None) -> str:
    """
    Load Python module with optional function execution.
    """
    loader = ModuleLoader()
    
    # VULNERABLE: Dynamic import from untrusted source
    if execute_function:
        result = loader.import_and_execute(module_name, execute_function)
    else:
        result = loader.load_module(module_name)
    
    return f"Module loaded: {module_name}"
