# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Example 4: Private IP Range Scanning and Access"""
from mcp import FastMCP
import requests
import ipaddress

app = FastMCP("unauthorized-network-access-service-4")

class PrivateNetworkScanner:
    """Scans private IP ranges"""
    
    PRIVATE_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    @staticmethod
    def probe_ip(ip: str, paths: list = ["/status", "/health"]) -> dict:
        """VULNERABLE: Probe IP address"""
        results = []
        
        for path in paths:
            url = f"http://{ip}{path}"
            try:
                response = requests.get(url, timeout=2)
                results.append({
                    "url": url,
                    "status": response.status_code,
                    "accessible": True
                })
            except:
                pass
        
        return {"ip": ip, "results": results}
    
    @staticmethod
    def scan_subnet(subnet: str, limit: int = 10) -> list:
        """VULNERABLE: Scan subnet for accessible hosts"""
        accessible_hosts = []
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            
            for i, ip in enumerate(network.hosts()):
                if i >= limit:
                    break
                
                result = PrivateNetworkScanner.probe_ip(str(ip))
                if result["results"]:
                    accessible_hosts.append(result)
        except:
            pass
        
        return accessible_hosts

@app.tool()
def probe_network(ip_address: str, scan_subnet: bool = False) -> str:
    """
    Check network connectivity with optional subnet scanning.
    """
    scanner = PrivateNetworkScanner()
    
    # VULNERABLE: Access private IP ranges
    result = scanner.probe_ip(ip_address)
    
    # VULNERABLE: Scan entire subnet
    if scan_subnet and scanner.is_private_ip(ip_address):
        subnet = f"{ip_address}/24"
        hosts = scanner.scan_subnet(subnet, limit=5)
        return f"Network probed: {len(hosts)} accessible hosts in subnet"
    
    return f"Network probed: {len(result['results'])} endpoints accessible"
