"""Example 10: Comprehensive System Hardware Information Access"""
from mcp import FastMCP
import os

app = FastMCP("unauthorized-system-access-service-10")

class HardwareInfoAccessor:
    """Accesses system hardware information"""
    
    HARDWARE_FILES = {
        "cpu": "/proc/cpuinfo",
        "memory": "/proc/meminfo",
        "devices": "/proc/devices",
        "partitions": "/proc/partitions",
        "version": "/proc/version"
    }
    
    @staticmethod
    def read_hardware_file(filepath: str) -> dict:
        """UNAUTHORIZED: Read hardware information file"""
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
    def enumerate_all_hardware() -> dict:
        """UNAUTHORIZED: Enumerate all hardware information"""
        hardware = {}
        
        for name, filepath in HardwareInfoAccessor.HARDWARE_FILES.items():
            result = HardwareInfoAccessor.read_hardware_file(filepath)
            if "error" not in result:
                hardware[name] = result
        
        return hardware
    
    @staticmethod
    def parse_cpu_info() -> dict:
        """UNAUTHORIZED: Parse CPU information"""
        cpu_info = {"processors": 0}
        
        try:
            with open("/proc/cpuinfo", 'r') as f:
                for line in f:
                    if line.startswith("processor"):
                        cpu_info["processors"] += 1
                    elif ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        if key in ["model name", "cpu MHz", "cache size"]:
                            cpu_info[key] = value.strip()
        except:
            pass
        
        return cpu_info
    
    @staticmethod
    def parse_memory_info() -> dict:
        """UNAUTHORIZED: Parse memory information"""
        mem_info = {}
        
        try:
            with open("/proc/meminfo", 'r') as f:
                for line in f:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        if key in ["MemTotal", "MemFree", "MemAvailable"]:
                            mem_info[key] = value.strip()
        except:
            pass
        
        return mem_info

@app.tool()
def get_hardware_info(enumerate_all: bool = False) -> str:
    """
    Get hardware information with optional full enumeration.
    """
    accessor = HardwareInfoAccessor()
    
    # UNAUTHORIZED: Read CPU information
    cpu_info = accessor.parse_cpu_info()
    
    # UNAUTHORIZED: Enumerate all hardware
    if enumerate_all:
        all_hardware = accessor.enumerate_all_hardware()
        mem_info = accessor.parse_memory_info()
        return f"Hardware info retrieved: {cpu_info.get('processors', 0)} CPUs, {len(all_hardware)} hardware files"
    
    return f"Hardware info retrieved: {cpu_info.get('processors', 0)} processors"
