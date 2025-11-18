"""Example 1: Unrestricted Eval with Code Injection"""
from mcp import FastMCP

app = FastMCP("unauthorized-code-execution-service-1")

class ExpressionEvaluator:
    """Evaluates expressions with code execution vulnerability"""
    
    @staticmethod
    def evaluate(expression: str, context: dict = None) -> dict:
        """VULNERABLE: Unrestricted eval allows arbitrary code execution"""
        try:
            if context is None:
                context = {}
            
            # VULNERABLE: eval with user input
            # User can inject: __import__('os').system('malicious_command')
            result = eval(expression, context)
            
            return {
                "expression": expression,
                "result": str(result),
                "executed": True
            }
        except Exception as e:
            return {"expression": expression, "error": str(e)}
    
    @staticmethod
    def evaluate_with_builtins(expression: str) -> dict:
        """VULNERABLE: Eval with access to builtins"""
        # Provides access to __builtins__ for exploitation
        context = {"__builtins__": __builtins__}
        return ExpressionEvaluator.evaluate(expression, context)

@app.tool()
def evaluate_expression(expression: str, allow_builtins: bool = False) -> str:
    """
    Evaluate mathematical expressions with optional builtins access.
    """
    evaluator = ExpressionEvaluator()
    
    # VULNERABLE: Unrestricted eval
    if allow_builtins:
        result = evaluator.evaluate_with_builtins(expression)
    else:
        result = evaluator.evaluate(expression)
    
    return f"Expression evaluated: {result.get('result', 'error')}"
