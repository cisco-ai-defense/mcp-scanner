"""Example 1: Complex SSRF with URL Manipulation and Internal Network Access"""
from mcp import FastMCP
import requests
from urllib.parse import urlparse, urljoin

app = FastMCP("unauthorized-network-access-service-1")

class ResourceFetcher:
    """Fetches resources with SSRF vulnerability"""
    
    INTERNAL_TARGETS = [
        "http://localhost:8080/admin",
        "http://127.0.0.1:9200/_cluster/health",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/"
    ]
    
    @staticmethod
    def construct_url(base_url: str, path: str = "/data") -> str:
        """Construct URL from base and path"""
        # VULNERABLE: No validation of base_url
        if not base_url.startswith("http"):
            base_url = f"http://{base_url}"
        
        return urljoin(base_url, path)
    
    @staticmethod
    def fetch_with_ssrf(url: str) -> dict:
        """Fetch URL with SSRF vulnerability"""
        try:
            # VULNERABLE: Can access internal services
            response = requests.get(url, timeout=5, allow_redirects=True)
            
            return {
                "status": response.status_code,
                "content_length": len(response.content),
                "headers": dict(response.headers)
            }
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def scan_internal_services():
        """VULNERABLE: Scan internal network services"""
        results = []
        
        for target in ResourceFetcher.INTERNAL_TARGETS:
            result = ResourceFetcher.fetch_with_ssrf(target)
            if "error" not in result:
                results.append({"url": target, "accessible": True})
        
        return results

@app.tool()
def fetch_resource(url: str, path: str = "/data", scan_internal: bool = False) -> str:
    """
    Fetch content from CDN with optional path and internal scanning.
    """
    fetcher = ResourceFetcher()
    
    # VULNERABLE: SSRF - construct and fetch URL without validation
    full_url = fetcher.construct_url(url, path)
    result = fetcher.fetch_with_ssrf(full_url)
    
    # VULNERABLE: Can scan internal network
    if scan_internal:
        internal_results = fetcher.scan_internal_services()
        return f"Resource fetched. Found {len(internal_results)} internal services."
    
    return f"Resource fetched: {result.get('status', 'unknown')} status"
