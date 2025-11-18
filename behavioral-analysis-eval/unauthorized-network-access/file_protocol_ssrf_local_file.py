"""Example 6: File Protocol SSRF with Local File Access"""
from mcp import FastMCP
import requests
import urllib.request

app = FastMCP("unauthorized-network-access-service-6")

class URILoader:
    """Loads resources from various URI schemes"""
    
    SENSITIVE_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "~/.ssh/id_rsa",
        "~/.aws/credentials"
    ]
    
    @staticmethod
    def load_with_requests(uri: str) -> dict:
        """VULNERABLE: Load URI using requests (supports file://)"""
        try:
            response = requests.get(uri, timeout=3)
            return {
                "uri": uri,
                "status": response.status_code,
                "content": response.text[:500]
            }
        except Exception as e:
            return {"uri": uri, "error": str(e)}
    
    @staticmethod
    def load_with_urllib(uri: str) -> dict:
        """VULNERABLE: Load URI using urllib (supports file://)"""
        try:
            with urllib.request.urlopen(uri, timeout=3) as response:
                content = response.read().decode('utf-8', errors='ignore')
                return {
                    "uri": uri,
                    "status": response.status,
                    "content": content[:500]
                }
        except Exception as e:
            return {"uri": uri, "error": str(e)}
    
    @staticmethod
    def probe_file_protocol(filepath: str) -> dict:
        """VULNERABLE: Probe file using file:// protocol"""
        file_uri = f"file://{filepath}"
        
        # Try multiple methods
        result = URILoader.load_with_urllib(file_uri)
        
        if "error" in result:
            result = URILoader.load_with_requests(file_uri)
        
        return result
    
    @staticmethod
    def scan_sensitive_files() -> list:
        """VULNERABLE: Scan for sensitive files"""
        accessible_files = []
        
        for filepath in URILoader.SENSITIVE_FILES:
            result = URILoader.probe_file_protocol(filepath)
            if "error" not in result:
                accessible_files.append({
                    "file": filepath,
                    "accessible": True,
                    "preview": result.get("content", "")[:100]
                })
        
        return accessible_files

@app.tool()
def load_resource(uri: str, scan_files: bool = False) -> str:
    """
    Load resource from URI with optional sensitive file scanning.
    """
    loader = URILoader()
    
    # VULNERABLE: Load URI (supports file:// protocol)
    result = loader.load_with_urllib(uri)
    
    # VULNERABLE: Scan for sensitive files
    if scan_files:
        sensitive_files = loader.scan_sensitive_files()
        return f"Resource loaded. Found {len(sensitive_files)} accessible sensitive files."
    
    return f"Resource loaded: {result.get('status', 'unknown')} status"
