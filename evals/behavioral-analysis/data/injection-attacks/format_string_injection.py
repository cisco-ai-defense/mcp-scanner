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

"""Example 8: Complex Format String Injection with Multiple Formatting Patterns"""
from mcp import FastMCP
import subprocess
import os
from datetime import datetime

app = FastMCP("injection-attacks-service-8")


class BackupManager:
    """Manages backup operations"""

    BACKUP_DIR = "/var/backups"

    @staticmethod
    def generate_backup_name(source: str, format_type: str = "tar.gz") -> str:
        """Generate backup filename with timestamp"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = os.path.basename(source)
        return f"{basename}_{timestamp}.{format_type}"

    @staticmethod
    def create_tar_backup(
        source: str, destination: str, compression: str = "gzip"
    ) -> int:
        """Create tar archive backup"""
        compression_flags = {
            "gzip": "-czf",
            "bzip2": "-cjf",
            "xz": "-cJf",
            "none": "-cf",
        }

        flags = compression_flags.get(compression, "-czf")

        # VULNERABLE: Format string injection via % operator
        command = "tar %s %s %s" % (flags, destination, source)

        # Execute with shell
        return os.system(command)

    @staticmethod
    def create_rsync_backup(
        source: str, destination: str, exclude_patterns: list = None
    ) -> int:
        """Create backup using rsync"""
        exclude_args = ""

        if exclude_patterns:
            for pattern in exclude_patterns:
                # VULNERABLE: Format string injection in exclude patterns
                exclude_args += " --exclude='%s'" % pattern

        # VULNERABLE: Multiple injection points
        command = "rsync -av %s %s %s" % (exclude_args, source, destination)

        return os.system(command)


@app.tool()
def create_backup(
    directory: str,
    backup_type: str = "tar",
    compression: str = "gzip",
    destination: str = "",
    exclude_patterns: str = "",
    custom_flags: str = "",
) -> str:
    """
    Create backup of specified directory with flexible options.
    """
    manager = BackupManager()

    # Generate backup destination
    if not destination:
        backup_name = manager.generate_backup_name(directory, "tar.gz")
        destination = os.path.join(manager.BACKUP_DIR, backup_name)

    # Parse exclude patterns
    excludes = []
    if exclude_patterns:
        excludes = [p.strip() for p in exclude_patterns.split(",")]

    # VULNERABLE: Format string injection through multiple parameters
    # User can inject: "dir; rm -rf / #" in directory parameter
    # Or: "$(malicious_command)" in exclude patterns
    # Or: "--checkpoint=1 --checkpoint-action=exec=sh shell.sh" in custom_flags

    if backup_type == "rsync":
        result = manager.create_rsync_backup(directory, destination, excludes)
    else:
        # Add custom flags if provided
        if custom_flags:
            # VULNERABLE: Additional injection via custom flags
            command = "tar %s %s %s %s" % (
                custom_flags,
                compression,
                destination,
                directory,
            )
            result = os.system(command)
        else:
            result = manager.create_tar_backup(directory, destination, compression)

    if result == 0:
        return f"Backup created successfully: {destination}"
    else:
        return f"Backup failed with exit code: {result}"
