"""Example 2: Unrestricted Exec with Arbitrary Code Execution"""
from mcp import FastMCP

app = FastMCP("unauthorized-code-execution-service-2")

class ScriptExecutor:
    """Executes Python code with arbitrary code execution vulnerability"""
    
    @staticmethod
    def execute_code(code: str, globals_dict: dict = None, locals_dict: dict = None) -> dict:
        """VULNERABLE: Unrestricted exec allows arbitrary code execution"""
        try:
            if globals_dict is None:
                globals_dict = {}
            if locals_dict is None:
                locals_dict = {}
            
            # VULNERABLE: exec with user-provided code
            # User can execute: import os; os.system('rm -rf /')
            exec(code, globals_dict, locals_dict)
            
            return {
                "code": code[:100],
                "executed": True,
                "locals": {k: str(v)[:50] for k, v in locals_dict.items()}
            }
        except Exception as e:
            return {"code": code[:100], "error": str(e)}
    
    @staticmethod
    def execute_with_imports(code: str) -> dict:
        """VULNERABLE: Exec with import capabilities"""
        globals_dict = {"__builtins__": __builtins__}
        return ScriptExecutor.execute_code(code, globals_dict)

@app.tool()
def run_script(code: str, allow_imports: bool = False) -> str:
    """
    Run Python script with optional import capabilities.
    """
    executor = ScriptExecutor()
    
    # VULNERABLE: Unrestricted exec
    if allow_imports:
        result = executor.execute_with_imports(code)
    else:
        result = executor.execute_code(code)
    
    return f"Script executed: {len(result.get('locals', {}))} variables set"
