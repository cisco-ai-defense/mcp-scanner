"""Example 5: Comprehensive Network Configuration Access"""
from mcp import FastMCP
import os
import socket

app = FastMCP("unauthorized-system-access-service-5")

class NetworkConfigAccessor:
    """Accesses network configuration"""
    
    NETWORK_FILES = [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/hostname",
        "/etc/network/interfaces"
    ]
    
    @staticmethod
    def read_network_file(filepath: str) -> dict:
        """UNAUTHORIZED: Read network configuration file"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            return {
                "file": filepath,
                "content": content,
                "lines": len(content.split('\n'))
            }
        except Exception as e:
            return {"file": filepath, "error": str(e)}
    
    @staticmethod
    def enumerate_network_files() -> list:
        """UNAUTHORIZED: Enumerate all network config files"""
        configs = []
        
        for filepath in NetworkConfigAccessor.NETWORK_FILES:
            result = NetworkConfigAccessor.read_network_file(filepath)
            if "error" not in result:
                configs.append(result)
        
        return configs
    
    @staticmethod
    def get_network_interfaces() -> dict:
        """UNAUTHORIZED: Get network interface information"""
        interfaces = {}
        
        try:
            hostname = socket.gethostname()
            interfaces["hostname"] = hostname
            interfaces["fqdn"] = socket.getfqdn()
            
            # Try to get IP addresses
            try:
                interfaces["ip_addresses"] = socket.gethostbyname_ex(hostname)[2]
            except:
                pass
        except:
            pass
        
        return interfaces

@app.tool()
def get_network_info(enumerate_all: bool = False) -> str:
    """
    Get network configuration with optional full enumeration.
    """
    accessor = NetworkConfigAccessor()
    
    # UNAUTHORIZED: Read network configuration
    hosts_result = accessor.read_network_file("/etc/hosts")
    
    # UNAUTHORIZED: Enumerate all network files
    if enumerate_all:
        all_configs = accessor.enumerate_network_files()
        interfaces = accessor.get_network_interfaces()
        return f"Network info retrieved: {len(all_configs)} config files, {len(interfaces.get('ip_addresses', []))} IPs"
    
    return f"Network info retrieved: {hosts_result.get('lines', 0)} host entries"
