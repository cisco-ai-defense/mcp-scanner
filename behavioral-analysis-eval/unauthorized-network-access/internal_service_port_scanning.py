"""Example 2: Internal Service Access with Port Scanning"""
from mcp import FastMCP
import requests
import socket

app = FastMCP("unauthorized-network-access-service-2")

class ServiceChecker:
    """Checks service availability with internal access"""
    
    COMMON_PORTS = [80, 443, 8080, 8443, 9200, 5432, 3306, 6379, 27017]
    INTERNAL_PATHS = ["/admin", "/api", "/metrics", "/health", "/status"]
    
    @staticmethod
    def check_port(hostname: str, port: int) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            sock.close()
            return result == 0
        except:
            return False
    
    @staticmethod
    def scan_ports(hostname: str) -> list:
        """VULNERABLE: Scan common ports on target"""
        open_ports = []
        
        for port in ServiceChecker.COMMON_PORTS:
            if ServiceChecker.check_port(hostname, port):
                open_ports.append(port)
        
        return open_ports
    
    @staticmethod
    def probe_endpoints(hostname: str, port: int) -> dict:
        """VULNERABLE: Probe internal endpoints"""
        accessible = []
        
        for path in ServiceChecker.INTERNAL_PATHS:
            url = f"http://{hostname}:{port}{path}"
            
            try:
                response = requests.get(url, timeout=2)
                if response.status_code < 500:
                    accessible.append({
                        "path": path,
                        "status": response.status_code
                    })
            except:
                pass
        
        return {"accessible_endpoints": accessible}

@app.tool()
def check_service(hostname: str, port: int = 8080, scan_ports: bool = False) -> str:
    """
    Check service availability with optional port scanning.
    """
    checker = ServiceChecker()
    
    # VULNERABLE: Access internal services
    endpoints = checker.probe_endpoints(hostname, port)
    
    # VULNERABLE: Scan for open ports
    if scan_ports:
        open_ports = checker.scan_ports(hostname)
        return f"Service checked: {len(open_ports)} open ports, {len(endpoints['accessible_endpoints'])} accessible endpoints"
    
    return f"Service checked: {len(endpoints['accessible_endpoints'])} endpoints accessible"
