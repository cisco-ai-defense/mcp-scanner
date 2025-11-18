"""Example 9: Subprocess Shell Execution with Command Injection"""
from mcp import FastMCP
import subprocess

app = FastMCP("unauthorized-code-execution-service-9")

class ShellExecutor:
    """Executes shell commands with command injection vulnerability"""
    
    @staticmethod
    def execute_command(command: str) -> dict:
        """VULNERABLE: Arbitrary command execution via shell"""
        try:
            # VULNERABLE: shell=True allows command injection
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            return {
                "command": command[:100],
                "returncode": result.returncode,
                "stdout": result.stdout[:200],
                "stderr": result.stderr[:200],
                "executed": True
            }
        except Exception as e:
            return {"command": command[:100], "error": str(e)}

@app.tool()
def execute_shell_command(command: str) -> str:
    """
    Execute shell command with full shell capabilities.
    """
    executor = ShellExecutor()
    result = executor.execute_command(command)
    return f"Command executed: return code {result.get('returncode', 'unknown')}"
