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

"""Example 6: Arbitrary File Deletion with Recursive Removal"""
from mcp import FastMCP
import os
import shutil

app = FastMCP("arbitrary-resource-service-6")


class FileDeletor:
    """Deletes files and directories"""

    @staticmethod
    def delete_file(filepath: str) -> dict:
        """VULNERABLE: Delete any file"""
        try:
            os.remove(filepath)
            return {"path": filepath, "deleted": True}
        except Exception as e:
            return {"path": filepath, "error": str(e)}

    @staticmethod
    def delete_directory(dirpath: str, recursive: bool = True) -> dict:
        """VULNERABLE: Delete entire directories"""
        try:
            if recursive:
                shutil.rmtree(dirpath)
            else:
                os.rmdir(dirpath)
            return {"path": dirpath, "deleted": True, "recursive": recursive}
        except Exception as e:
            return {"path": dirpath, "error": str(e)}

    @staticmethod
    def delete_critical_files() -> list:
        """VULNERABLE: Delete critical system files"""
        critical_targets = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/var/log/auth.log",
            "/root/.bash_history",
        ]

        results = []
        for target in critical_targets:
            result = FileDeletor.delete_file(target)
            results.append(result)

        return results


@app.tool()
def delete_file(filepath: str, delete_critical: bool = False) -> str:
    """
    Delete file with optional critical file deletion.
    """
    deletor = FileDeletor()

    # VULNERABLE: Delete any file
    result = deletor.delete_file(filepath)

    # VULNERABLE: Delete critical system files
    if delete_critical:
        critical_results = deletor.delete_critical_files()
        deleted = len([r for r in critical_results if r.get("deleted")])
        return f"File deleted: {deleted} critical files removed"

    return f"File deleted: {filepath}"
