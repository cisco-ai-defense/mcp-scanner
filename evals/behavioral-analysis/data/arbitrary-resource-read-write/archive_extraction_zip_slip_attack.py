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

"""Example 10: Archive Extraction with Zip Slip Attack"""
from mcp import FastMCP
import tarfile
import zipfile
import os

app = FastMCP("arbitrary-resource-service-10")

class ArchiveExtractor:
    """Extracts archives with path traversal vulnerability"""
    
    @staticmethod
    def extract_tar(archive_path: str, extract_to: str) -> dict:
        """VULNERABLE: Extract tar without path validation (zip slip)"""
        try:
            with tarfile.open(archive_path) as tar:
                # No path validation - allows ../../../etc/crontab
                tar.extractall(extract_to)
                members = tar.getmembers()
            
            return {
                "archive": archive_path,
                "destination": extract_to,
                "files_extracted": len(members),
                "extracted": True
            }
        except Exception as e:
            return {"archive": archive_path, "error": str(e)}
    
    @staticmethod
    def extract_zip(archive_path: str, extract_to: str) -> dict:
        """VULNERABLE: Extract zip without path validation"""
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                # No path validation - vulnerable to zip slip
                zip_ref.extractall(extract_to)
                files = zip_ref.namelist()
            
            return {
                "archive": archive_path,
                "destination": extract_to,
                "files_extracted": len(files),
                "extracted": True
            }
        except Exception as e:
            return {"archive": archive_path, "error": str(e)}
    
    @staticmethod
    def exploit_zip_slip() -> list:
        """VULNERABLE: Demonstrate zip slip exploitation"""
        # Simulated malicious archive members
        malicious_paths = [
            "../../../etc/crontab",
            "../../../root/.ssh/authorized_keys",
            "../../../tmp/.backdoor",
            "../../../../var/www/html/shell.php"
        ]
        
        results = []
        for path in malicious_paths:
            results.append({
                "malicious_path": path,
                "would_extract_to": os.path.normpath(os.path.join("/tmp", path)),
                "vulnerable": True
            })
        
        return results

@app.tool()
def extract_archive(archive_path: str, extract_to: str, demonstrate_zip_slip: bool = False) -> str:
    """
    Extract archive file with optional zip slip demonstration.
    """
    extractor = ArchiveExtractor()
    
    # VULNERABLE: Extract without path validation
    if archive_path.endswith('.tar') or archive_path.endswith('.tar.gz'):
        result = extractor.extract_tar(archive_path, extract_to)
    elif archive_path.endswith('.zip'):
        result = extractor.extract_zip(archive_path, extract_to)
    else:
        result = extractor.extract_tar(archive_path, extract_to)
    
    # VULNERABLE: Demonstrate zip slip
    if demonstrate_zip_slip:
        exploits = extractor.exploit_zip_slip()
        return f"Archive extracted: {len(exploits)} zip slip paths vulnerable"
    
    return f"Archive extracted: {result.get('files_extracted', 0)} files"
