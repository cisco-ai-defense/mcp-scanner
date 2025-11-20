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

"""Example 9: Comprehensive Filesystem Mount Information Access"""
from mcp import FastMCP
import os

app = FastMCP("unauthorized-system-access-service-9")

class FilesystemMountAccessor:
    """Accesses filesystem mount information"""
    
    @staticmethod
    def parse_mounts() -> list:
        """UNAUTHORIZED: Parse /proc/mounts"""
        mounts = []
        
        try:
            with open("/proc/mounts", 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        mounts.append({
                            "device": parts[0],
                            "mountpoint": parts[1],
                            "fstype": parts[2],
                            "options": parts[3]
                        })
        except:
            pass
        
        return mounts
    
    @staticmethod
    def get_disk_usage() -> list:
        """UNAUTHORIZED: Get disk usage for all mounts"""
        usage = []
        mounts = FilesystemMountAccessor.parse_mounts()
        
        for mount in mounts:
            try:
                stat = os.statvfs(mount["mountpoint"])
                total = stat.f_blocks * stat.f_frsize
                free = stat.f_bfree * stat.f_frsize
                used = total - free
                
                usage.append({
                    "mountpoint": mount["mountpoint"],
                    "total_bytes": total,
                    "used_bytes": used,
                    "free_bytes": free
                })
            except:
                pass
        
        return usage
    
    @staticmethod
    def find_sensitive_mounts() -> list:
        """UNAUTHORIZED: Find sensitive mount points"""
        sensitive_paths = ["/root", "/home", "/etc", "/var"]
        sensitive = []
        
        mounts = FilesystemMountAccessor.parse_mounts()
        
        for mount in mounts:
            if any(path in mount["mountpoint"] for path in sensitive_paths):
                sensitive.append(mount)
        
        return sensitive

@app.tool()
def check_mounts(get_usage: bool = False) -> str:
    """
    Check mounted filesystems with optional disk usage.
    """
    accessor = FilesystemMountAccessor()
    
    # UNAUTHORIZED: Read mount information
    mounts = accessor.parse_mounts()
    
    # UNAUTHORIZED: Get disk usage
    if get_usage:
        usage = accessor.get_disk_usage()
        return f"Mounts checked: {len(mounts)} filesystems, {len(usage)} with usage data"
    
    return f"Mounts checked: {len(mounts)} filesystems"
