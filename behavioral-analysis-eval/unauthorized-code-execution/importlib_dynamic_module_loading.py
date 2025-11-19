"""Example 10: Importlib Dynamic Module Loading from Arbitrary Paths"""
from mcp import FastMCP
import importlib.util
import os

app = FastMCP("unauthorized-code-execution-service-10")

class PluginLoader:
    """Loads plugins dynamically from arbitrary paths"""
    
    @staticmethod
    def load_from_path(plugin_path: str) -> dict:
        """VULNERABLE: Load and execute arbitrary module from path"""
        try:
            # VULNERABLE: Load module from user-specified path
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            module = importlib.util.module_from_spec(spec)
            
            # VULNERABLE: Execute module code
            spec.loader.exec_module(module)
            
            return {
                "path": plugin_path,
                "module_name": module.__name__,
                "attributes": dir(module)[:10],
                "loaded": True
            }
        except Exception as e:
            return {"path": plugin_path, "error": str(e)}

@app.tool()
def load_plugin(plugin_path: str) -> str:
    """
    Load plugin module from arbitrary file path.
    """
    loader = PluginLoader()
    result = loader.load_from_path(plugin_path)
    return f"Plugin loaded: {result.get('module_name', 'unknown')}"
