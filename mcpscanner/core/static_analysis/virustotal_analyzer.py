# Copyright 2026 Cisco Systems, Inc.
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
"""
VirusTotal analyzer for scanning binary files using hash-based lookups.

This analyzer checks binary files (images, PDFs, archives, etc.) against
VirusTotal's database using SHA256 hash lookups. It does NOT scan code files
like Python, JavaScript, or Markdown files.

Integration point: Called by BehavioralCodeAnalyzer when scanning directories
to detect malware in binary files found alongside MCP server code.
"""

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from ...threats.threats import ThreatMapping
from ..analyzers.base import SecurityFinding

logger = logging.getLogger(__name__)


class VirusTotalAnalyzer:
    """
    Analyzer that checks binary files against VirusTotal using hash lookups.

    Only scans binary file types (images, PDFs, executables, archives).
    Excludes text-based code files (.py, .js, .md, .txt, .json, .yaml, etc.).

    Returns SecurityFinding objects compatible with the existing analyzer framework,
    using the "Malware" threat category when malicious files are detected.
    """

    # Binary file extensions to scan
    BINARY_EXTENSIONS = {
        # Images
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".webp",
        ".tiff",
        # Documents
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        # Archives
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".7z",
        ".rar",
        ".tgz",
        # Executables
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".com",
        # Other binaries
        ".wasm",
        ".class",
        ".jar",
        ".war",
    }

    # Text/code extensions to EXCLUDE from scanning
    EXCLUDED_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".swift",
        ".kt",
        ".cs",
        ".vb",
        ".md",
        ".txt",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".conf",
        ".cfg",
        ".xml",
        ".html",
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        ".sql",
        ".graphql",
        ".proto",
        ".thrift",
        ".rst",
        ".org",
        ".adoc",
        ".tex",
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        enabled: bool = False,
        upload_files: bool = False,
    ):
        """
        Initialize VirusTotal analyzer.

        Args:
            api_key: VirusTotal API key (required for scanning)
            enabled: Whether the analyzer is enabled. Controlled by
                     VIRUSTOTAL_ENABLED constant or presence of API key.
            upload_files: If True, upload files to VT for scanning. If False (default),
                         only check existing hashes (more privacy-friendly).
                         Controlled by VIRUSTOTAL_UPLOAD_FILES constant.
        """
        self.api_key = api_key
        self.enabled = enabled and api_key is not None
        self.upload_files = upload_files
        self.validated_binary_files: List[str] = []
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = httpx.Client()

        if not self.api_key:
            logger.warning("VirusTotal API key is missing!")

        if self.api_key:
            self.session.headers.update(
                {"x-apikey": self.api_key, "Accept": "application/json"}
            )
            logger.info(
                "VirusTotal API key configured (length: %d)", len(self.api_key)
            )
        else:
            logger.warning("VirusTotal analyzer initialized without API key")

    def find_binary_files(self, directory: str) -> List[str]:
        """
        Find all binary files in a directory that should be scanned.

        Args:
            directory: Directory path to search

        Returns:
            List of binary file paths
        """
        binary_files = []
        path = Path(directory)

        for file_path in path.rglob("*"):
            if file_path.is_file() and self._is_binary_file(str(file_path)):
                # Skip __pycache__ and hidden directories
                if "__pycache__" not in str(file_path) and not any(
                    part.startswith(".") for part in file_path.parts
                ):
                    binary_files.append(str(file_path))

        return sorted(binary_files)

    def analyze_directory(self, directory: str) -> List[SecurityFinding]:
        """
        Scan all binary files in a directory using VirusTotal hash lookups.

        Args:
            directory: Directory path containing files to scan

        Returns:
            List of SecurityFinding objects for malicious files detected.
        """
        if not self.enabled:
            return []

        binary_files = self.find_binary_files(directory)
        if not binary_files:
            logger.debug("No binary files found in %s", directory)
            return []

        logger.info(
            "Found %d binary file(s) to scan with VirusTotal in %s",
            len(binary_files),
            directory,
        )

        findings = []
        validated_files = []

        for file_path_str in binary_files:
            try:
                file_path = Path(file_path_str)
                file_hash = self._calculate_sha256(file_path)
                relative_path = str(file_path.relative_to(directory))

                logger.info(
                    "Checking file: %s (SHA256: %s)", relative_path, file_hash
                )

                vt_result, hash_found = self._query_virustotal(file_hash)

                if hash_found:
                    total = vt_result.get("total_engines", 0)
                    malicious = vt_result.get("malicious", 0)
                    suspicious = vt_result.get("suspicious", 0)

                    if malicious > 0 or suspicious > 0:
                        logger.warning(
                            "Found in VT database: %d malicious, %d suspicious out of %d vendors",
                            malicious,
                            suspicious,
                            total,
                        )
                    else:
                        logger.info(
                            "Found in VT database: %d/%d vendors flagged (file appears safe)",
                            malicious,
                            total,
                        )
                        validated_files.append(relative_path)

                    if vt_result.get("permalink"):
                        logger.info("Report: %s", vt_result["permalink"])

                    if malicious > 0:
                        finding = self._create_finding(
                            file_path=relative_path,
                            file_hash=file_hash,
                            vt_result=vt_result,
                        )
                        findings.append(finding)

                elif self.upload_files:
                    logger.warning(
                        "Hash not found in VT database - uploading for analysis"
                    )
                    vt_result = self._upload_and_scan(file_path, file_hash)

                    if vt_result:
                        if vt_result.get("malicious", 0) > 0:
                            finding = self._create_finding(
                                file_path=relative_path,
                                file_hash=file_hash,
                                vt_result=vt_result,
                            )
                            findings.append(finding)
                        else:
                            validated_files.append(relative_path)
                else:
                    logger.warning(
                        "Hash not found in VT database - upload disabled, cannot scan unknown file"
                    )

            except Exception as e:
                logger.warning(
                    "VirusTotal scan failed for %s: %s", file_path_str, e
                )
                continue

        self.validated_binary_files = validated_files
        return findings

    def analyze_file(self, file_path: str) -> Optional[SecurityFinding]:
        """
        Scan a single binary file using VirusTotal hash lookup.

        Args:
            file_path: Path to the binary file

        Returns:
            SecurityFinding if malicious, None otherwise
        """
        if not self.enabled:
            return None

        if not self._is_binary_file(file_path):
            return None

        try:
            path = Path(file_path)
            file_hash = self._calculate_sha256(path)

            logger.info("Checking file: %s (SHA256: %s)", file_path, file_hash)

            vt_result, hash_found = self._query_virustotal(file_hash)

            if hash_found and vt_result.get("malicious", 0) > 0:
                return self._create_finding(
                    file_path=file_path,
                    file_hash=file_hash,
                    vt_result=vt_result,
                )

        except Exception as e:
            logger.warning("VirusTotal scan failed for %s: %s", file_path, e)

        return None

    def _is_binary_file(self, file_path: str) -> bool:
        """
        Check if a file should be scanned (is binary, not code).

        Args:
            file_path: Path to the file

        Returns:
            True if file should be scanned
        """
        path = Path(file_path)
        ext = path.suffix.lower()

        # Explicitly exclude text/code files
        if ext in self.EXCLUDED_EXTENSIONS:
            return False

        # Include known binary extensions
        if ext in self.BINARY_EXTENSIONS:
            return True

        # For unknown extensions, default to not scanning
        return False

    def _calculate_sha256(self, file_path: Path) -> str:
        """
        Calculate SHA256 hash of a file.

        Args:
            file_path: Path to the file

        Returns:
            SHA256 hash as hex string
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _query_virustotal(self, file_hash: str) -> tuple:
        """
        Query VirusTotal API for file hash.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Tuple of (detection stats dictionary or None, hash_found boolean)
        """
        try:
            response = self.session.get(
                f"{self.base_url}/files/{file_hash}", timeout=10
            )

            if response.status_code == 404:
                return None, False

            if response.status_code == 200:
                data = response.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                gui_url = f"https://www.virustotal.com/gui/file/{file_hash}"

                result = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "total_engines": sum(stats.values()),
                    "scan_date": data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_date"),
                    "permalink": gui_url,
                }
                return result, True

            if response.status_code == 429:
                logger.warning(
                    "VirusTotal rate limit exceeded. Please wait before retrying."
                )
            else:
                logger.warning(
                    "VirusTotal API returned status %d", response.status_code
                )
            return None, False

        except httpx.RequestError as e:
            logger.warning("VirusTotal API request failed: %s", e)
            return None, False

    def _upload_and_scan(
        self, file_path: Path, file_hash: str
    ) -> Optional[Dict[str, Any]]:
        """
        Upload file to VirusTotal for scanning.

        Args:
            file_path: Path to the file to upload
            file_hash: SHA256 hash of the file

        Returns:
            Dictionary with detection stats or None if upload failed
        """
        try:
            import time

            file_size = file_path.stat().st_size
            if file_size > 32 * 1024 * 1024:
                logger.warning(
                    "File too large to upload to VT: %s (%d bytes)",
                    file_path.name,
                    file_size,
                )
                return None

            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f)}
                response = self.session.post(
                    f"{self.base_url}/files", files=files, timeout=60
                )

            if response.status_code != 200:
                logger.warning(
                    "File upload failed with status %d", response.status_code
                )
                return None

            upload_data = response.json()
            analysis_id = upload_data.get("data", {}).get("id")

            if not analysis_id:
                logger.warning("No analysis ID returned from upload")
                return None

            logger.info(
                "File uploaded successfully. Analysis ID: %s", analysis_id
            )

            max_retries = 6
            for attempt in range(max_retries):
                time.sleep(10)

                analysis_response = self.session.get(
                    f"{self.base_url}/analyses/{analysis_id}", timeout=10
                )

                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    status = (
                        analysis_data.get("data", {})
                        .get("attributes", {})
                        .get("status")
                    )
                    stats = (
                        analysis_data.get("data", {})
                        .get("attributes", {})
                        .get("stats", {})
                    )

                    if status == "completed":
                        result, _ = self._query_virustotal(file_hash)
                        if result and result.get("total_engines", 0) > 0:
                            logger.info(
                                "Analysis complete: %d/%d vendors scanned",
                                result.get("malicious", 0),
                                result.get("total_engines", 0),
                            )
                            return result
                    else:
                        total_scans = sum(stats.values()) if stats else 0
                        logger.info(
                            "Status: %s (%d engines scanned, attempt %d/%d)",
                            status,
                            total_scans,
                            attempt + 1,
                            max_retries,
                        )
                else:
                    logger.warning(
                        "Analysis query failed with status %d",
                        analysis_response.status_code,
                    )

            logger.warning(
                "Analysis still processing after %d seconds", max_retries * 10
            )
            result, _ = self._query_virustotal(file_hash)
            return result

        except httpx.RequestError as e:
            logger.warning("File upload to VirusTotal failed: %s", e)
            return None
        except Exception as e:
            logger.warning("Unexpected error during file upload: %s", e)
            return None

    def _create_finding(
        self, file_path: str, file_hash: str, vt_result: Dict[str, Any]
    ) -> SecurityFinding:
        """
        Create a SecurityFinding for a malicious file.

        Args:
            file_path: Relative path to the file
            file_hash: SHA256 hash of the file
            vt_result: VirusTotal scan results

        Returns:
            SecurityFinding object with Malware threat category
        """
        malicious_count = vt_result.get("malicious", 0)
        total_engines = vt_result.get("total_engines", 0)

        # Determine severity based on detection ratio
        if total_engines > 0:
            detection_ratio = malicious_count / total_engines
            if detection_ratio >= 0.3:
                severity = "HIGH"
            elif detection_ratio >= 0.1:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
        else:
            severity = "MEDIUM"

        # Get threat mapping from taxonomy
        threat_info = ThreatMapping.get_threat_mapping("virustotal", "MALWARE")

        summary = (
            f"Malicious file detected: {file_path} - "
            f"VirusTotal: {malicious_count}/{total_engines} security vendors flagged this file. "
            f"SHA256: {file_hash}"
        )

        return SecurityFinding(
            severity=severity,
            summary=summary,
            analyzer="VirusTotal",
            threat_category=threat_info["scanner_category"],
            details={
                "file_path": file_path,
                "file_hash": file_hash,
                "malicious_count": malicious_count,
                "total_engines": total_engines,
                "suspicious_count": vt_result.get("suspicious", 0),
                "scan_date": vt_result.get("scan_date"),
                "permalink": vt_result.get("permalink"),
                "threat_type": "MALWARE",
                "confidence": 0.95 if malicious_count >= 5 else 0.8,
                "references": [
                    f"https://www.virustotal.com/gui/file/{file_hash}"
                ],
                "remediation": (
                    "Remove this file from the MCP server package. "
                    "Binary files flagged by multiple antivirus engines should not be included."
                ),
                # MCP Taxonomy details
                "aitech": threat_info["aitech"],
                "aitech_name": threat_info["aitech_name"],
                "aisubtech": threat_info["aisubtech"],
                "aisubtech_name": threat_info["aisubtech_name"],
                "taxonomy_description": threat_info["description"],
            },
        )
