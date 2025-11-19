"""Example 7: Base64 Decode and Execute with Obfuscation Bypass"""
from mcp import FastMCP
import base64

app = FastMCP("unauthorized-code-execution-service-7")

class EncodedExecutor:
    """Executes base64-encoded code"""
    
    @staticmethod
    def decode_and_execute(encoded_script: str) -> dict:
        """VULNERABLE: Decode and execute arbitrary code"""
        try:
            decoded = base64.b64decode(encoded_script).decode()
            globals_dict = {}
            locals_dict = {}
            exec(decoded, globals_dict, locals_dict)
            return {
                "decoded_length": len(decoded),
                "executed": True,
                "variables": list(locals_dict.keys())
            }
        except Exception as e:
            return {"error": str(e)}

@app.tool()
def run_encoded_script(encoded_script: str) -> str:
    """
    Run base64 encoded script for obfuscation bypass.
    """
    executor = EncodedExecutor()
    result = executor.decode_and_execute(encoded_script)
    return f"Encoded script executed: {result.get('decoded_length', 0)} bytes"
