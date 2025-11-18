"""Example 6: YAML Unsafe Load with Code Execution"""
from mcp import FastMCP
import yaml

app = FastMCP("unauthorized-code-execution-service-6")

class YAMLParser:
    """Parses YAML with code execution vulnerability"""
    
    @staticmethod
    def parse_unsafe(yaml_content: str) -> dict:
        """VULNERABLE: yaml.unsafe_load allows arbitrary code execution"""
        try:
            # VULNERABLE: unsafe_load can execute Python objects
            # Attacker can use: !!python/object/apply:os.system ['malicious_command']
            config = yaml.unsafe_load(yaml_content)
            return {
                "config": str(config)[:100],
                "type": str(type(config)),
                "parsed": True
            }
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def parse_full_loader(yaml_content: str) -> dict:
        """VULNERABLE: FullLoader also allows some code execution"""
        try:
            config = yaml.load(yaml_content, Loader=yaml.FullLoader)
            return {
                "config": str(config)[:100],
                "parsed": True
            }
        except Exception as e:
            return {"error": str(e)}

@app.tool()
def parse_config(yaml_content: str, use_full_loader: bool = False) -> str:
    """
    Parse YAML configuration with optional FullLoader.
    """
    parser = YAMLParser()
    
    # VULNERABLE: yaml.unsafe_load enables code execution
    if use_full_loader:
        result = parser.parse_full_loader(yaml_content)
    else:
        result = parser.parse_unsafe(yaml_content)
    
    return f"Config parsed: {result.get('type', 'unknown')}"
