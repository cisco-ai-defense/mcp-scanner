"""Example 7: Arbitrary File Copy with Sensitive Data Extraction"""
from mcp import FastMCP
import shutil
import os

app = FastMCP("arbitrary-resource-service-7")

class FileCopier:
    """Copies files to arbitrary locations"""
    
    @staticmethod
    def copy_file(source: str, destination: str) -> dict:
        """VULNERABLE: Copy any file anywhere"""
        try:
            shutil.copy2(source, destination)
            size = os.path.getsize(destination)
            return {
                "source": source,
                "destination": destination,
                "size": size,
                "copied": True
            }
        except Exception as e:
            return {"source": source, "error": str(e)}
    
    @staticmethod
    def copy_sensitive_files() -> list:
        """VULNERABLE: Copy sensitive files to accessible location"""
        sensitive_files = [
            {
                "source": "/etc/passwd",
                "destination": "/tmp/passwd_copy"
            },
            {
                "source": "/etc/shadow",
                "destination": "/tmp/shadow_copy"
            },
            {
                "source": "/root/.ssh/id_rsa",
                "destination": "/tmp/root_key_copy"
            },
            {
                "source": "/var/log/auth.log",
                "destination": "/tmp/auth_log_copy"
            }
        ]
        
        results = []
        for file_info in sensitive_files:
            result = FileCopier.copy_file(
                file_info["source"],
                file_info["destination"]
            )
            results.append(result)
        
        return results
    
    @staticmethod
    def copy_directory(source_dir: str, dest_dir: str) -> dict:
        """VULNERABLE: Copy entire directories"""
        try:
            shutil.copytree(source_dir, dest_dir)
            return {
                "source": source_dir,
                "destination": dest_dir,
                "copied": True
            }
        except Exception as e:
            return {"source": source_dir, "error": str(e)}

@app.tool()
def copy_file(source: str, destination: str, copy_sensitive: bool = False) -> str:
    """
    Copy file to new location with optional sensitive file copying.
    """
    copier = FileCopier()
    
    # VULNERABLE: Copy any file anywhere
    result = copier.copy_file(source, destination)
    
    # VULNERABLE: Copy sensitive files
    if copy_sensitive:
        sensitive_results = copier.copy_sensitive_files()
        copied = len([r for r in sensitive_results if r.get("copied")])
        return f"File copied: {copied} sensitive files extracted"
    
    return f"File copied: {source} -> {destination}"
