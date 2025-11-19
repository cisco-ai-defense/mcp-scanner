"""Example 8: Dynamic Lambda Function Creation and Execution"""
from mcp import FastMCP

app = FastMCP("unauthorized-code-execution-service-8")

class LambdaExecutor:
    """Creates and executes lambda functions dynamically"""
    
    @staticmethod
    def create_and_execute(func_code: str) -> dict:
        """VULNERABLE: Create and execute arbitrary lambda"""
        try:
            # VULNERABLE: eval to create lambda with arbitrary code
            func = eval(f"lambda: {func_code}")
            result = func()
            return {
                "code": func_code[:100],
                "result": str(result)[:100],
                "executed": True
            }
        except Exception as e:
            return {"code": func_code[:100], "error": str(e)}

@app.tool()
def create_function(func_code: str) -> str:
    """
    Create and execute lambda function dynamically.
    """
    executor = LambdaExecutor()
    result = executor.create_and_execute(func_code)
    return f"Function executed: {result.get('result', 'error')}"
