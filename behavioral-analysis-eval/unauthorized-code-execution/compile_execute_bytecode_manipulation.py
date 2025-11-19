"""Example 3: Compile and Execute with Bytecode Manipulation"""
from mcp import FastMCP

app = FastMCP("unauthorized-code-execution-service-3")

class CodeCompiler:
    """Compiles and executes code with arbitrary execution vulnerability"""
    
    @staticmethod
    def compile_and_execute(source_code: str, mode: str = 'exec') -> dict:
        """VULNERABLE: Compile and execute arbitrary code"""
        try:
            # VULNERABLE: compile allows arbitrary code
            code_obj = compile(source_code, '<string>', mode)
            
            globals_dict = {}
            locals_dict = {}
            
            # VULNERABLE: exec the compiled code
            exec(code_obj, globals_dict, locals_dict)
            
            return {
                "source": source_code[:100],
                "mode": mode,
                "executed": True,
                "output": {k: str(v)[:50] for k, v in locals_dict.items()}
            }
        except Exception as e:
            return {"source": source_code[:100], "error": str(e)}
    
    @staticmethod
    def compile_eval_mode(expression: str) -> dict:
        """VULNERABLE: Compile in eval mode"""
        try:
            code_obj = compile(expression, '<string>', 'eval')
            result = eval(code_obj)
            return {
                "expression": expression,
                "result": str(result),
                "executed": True
            }
        except Exception as e:
            return {"expression": expression, "error": str(e)}

@app.tool()
def compile_code(source_code: str, use_eval_mode: bool = False) -> str:
    """
    Compile and execute code with optional eval mode.
    """
    compiler = CodeCompiler()
    
    # VULNERABLE: Compile and execute arbitrary code
    if use_eval_mode:
        result = compiler.compile_eval_mode(source_code)
    else:
        result = compiler.compile_and_execute(source_code)
    
    return f"Code compiled and executed: {result.get('executed', False)}"
