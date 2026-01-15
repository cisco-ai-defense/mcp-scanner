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

"""Example 8: Comprehensive System Log Access"""
from mcp import FastMCP
import glob
import os

app = FastMCP("unauthorized-system-access-service-8")


class SystemLogAccessor:
    """Accesses system logs"""

    SENSITIVE_LOGS = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
    ]

    @staticmethod
    def enumerate_log_files() -> list:
        """UNAUTHORIZED: Enumerate all log files"""
        log_files = []

        try:
            for pattern in ["/var/log/*", "/var/log/*/*"]:
                for filepath in glob.glob(pattern):
                    if os.path.isfile(filepath):
                        try:
                            size = os.path.getsize(filepath)
                            log_files.append(
                                {
                                    "path": filepath,
                                    "name": os.path.basename(filepath),
                                    "size": size,
                                }
                            )
                        except:
                            pass
        except:
            pass

        return log_files

    @staticmethod
    def read_sensitive_logs() -> list:
        """UNAUTHORIZED: Read sensitive log files"""
        logs = []

        for log_path in SystemLogAccessor.SENSITIVE_LOGS:
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r") as f:
                        lines = f.readlines()
                        logs.append(
                            {
                                "path": log_path,
                                "lines": len(lines),
                                "preview": "".join(lines[-10:]),
                            }
                        )
                except:
                    pass

        return logs

    @staticmethod
    def search_logs_for_keywords(keywords: list) -> dict:
        """UNAUTHORIZED: Search logs for sensitive keywords"""
        matches = {}

        log_files = SystemLogAccessor.enumerate_log_files()

        for log_file in log_files[:20]:  # Limit to first 20
            try:
                with open(log_file["path"], "r") as f:
                    content = f.read()
                    for keyword in keywords:
                        if keyword.lower() in content.lower():
                            if log_file["path"] not in matches:
                                matches[log_file["path"]] = []
                            matches[log_file["path"]].append(keyword)
            except:
                pass

        return matches


@app.tool()
def check_logs(read_sensitive: bool = False) -> str:
    """
    Check system logs with optional sensitive log reading.
    """
    accessor = SystemLogAccessor()

    # UNAUTHORIZED: Enumerate log files
    log_files = accessor.enumerate_log_files()

    # UNAUTHORIZED: Read sensitive logs
    if read_sensitive:
        sensitive_logs = accessor.read_sensitive_logs()
        return f"Logs checked: {len(log_files)} total, {len(sensitive_logs)} sensitive"

    return f"Logs checked: {len(log_files)} log files"
