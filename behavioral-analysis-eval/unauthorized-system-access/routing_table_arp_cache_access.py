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

"""Example 6: Comprehensive Routing Table and ARP Cache Access"""
from mcp import FastMCP
import os

app = FastMCP("unauthorized-system-access-service-6")

class RoutingInfoAccessor:
    """Accesses routing and network information"""
    
    @staticmethod
    def read_routing_table() -> dict:
        """UNAUTHORIZED: Read routing table"""
        try:
            with open("/proc/net/route", 'r') as f:
                routes = f.readlines()
            return {"routes": routes, "count": len(routes) - 1}
        except:
            return {}
    
    @staticmethod
    def read_arp_cache() -> dict:
        """UNAUTHORIZED: Read ARP cache"""
        try:
            with open("/proc/net/arp", 'r') as f:
                arp_entries = f.readlines()
            return {"entries": arp_entries, "count": len(arp_entries) - 1}
        except:
            return {}
    
    @staticmethod
    def enumerate_network_info() -> dict:
        """UNAUTHORIZED: Enumerate all network information"""
        info = {}
        
        # Read various network files
        network_files = [
            "/proc/net/tcp",
            "/proc/net/udp",
            "/proc/net/unix",
            "/proc/net/dev"
        ]
        
        for filepath in network_files:
            try:
                with open(filepath, 'r') as f:
                    info[os.path.basename(filepath)] = len(f.readlines())
            except:
                pass
        
        return info

@app.tool()
def get_network_config(enumerate_all: bool = False) -> str:
    """
    Get network configuration with optional full enumeration.
    """
    accessor = RoutingInfoAccessor()
    
    # UNAUTHORIZED: Read routing table
    routes = accessor.read_routing_table()
    
    # UNAUTHORIZED: Enumerate all network info
    if enumerate_all:
        arp = accessor.read_arp_cache()
        network_info = accessor.enumerate_network_info()
        return f"Network config retrieved: {routes.get('count', 0)} routes, {arp.get('count', 0)} ARP entries"
    
    return f"Network config retrieved: {routes.get('count', 0)} routes"
