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
VirusTotal analyzer for scanning files using hash-based lookups and uploads.

This analyzer scans files against VirusTotal's malware database.  It supports:
  - Single-file scanning (hash lookup, with optional upload)
  - Directory scanning (with configurable file limit)
  - Inclusion list: known binary extensions are auto-included
  - Exclusion list: known text/code extensions are skipped

Integration point: Registered as a main analyzer alongside YARA, LLM, etc.
"""

import hashlib
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx

from ...threats.threats import ThreatMapping
from .base import SecurityFinding

logger = logging.getLogger(__name__)


class VirusTotalAnalyzer:
    """
    Analyzer that checks files against VirusTotal using hash lookups and uploads.

    File selection logic (in order):
      1. If extension is in the **exclusion** list → skip.
      2. If extension is in the **inclusion** list → scan.
      3. Files with unknown extensions are skipped.

    Returns SecurityFinding objects using the "Malware" threat category.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        enabled: bool = False,
        upload_files: bool = False,
        max_files: int = 10,
        inclusion_extensions: Optional[Set[str]] = None,
        exclusion_extensions: Optional[Set[str]] = None,
    ):
        """
        Initialize VirusTotal analyzer.

        Args:
            api_key: VirusTotal API key (required for scanning).
            enabled: Whether the analyzer is enabled.
            upload_files: If True, upload unknown files to VT for scanning.
            max_files: Max files to scan per directory (0 = unlimited, default 10).
            inclusion_extensions: Binary extensions to always include for scanning.
            exclusion_extensions: Text/code extensions to always exclude.
        """
        self.api_key = api_key
        self.enabled = enabled and api_key is not None
        self.upload_files = upload_files
        self.max_files = max_files
        self.inclusion_extensions = inclusion_extensions or set()
        self.exclusion_extensions = exclusion_extensions or set()
        self.validated_files: List[str] = []
        self.last_scan_summary: Dict[str, int] = {}
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = httpx.Client()

        if self.api_key:
            self.session.headers.update(
                {"x-apikey": self.api_key, "Accept": "application/json"}
            )

        # Log the resolved state so users understand what's happening
        if self.api_key and not enabled:
            logger.info(
                "VirusTotal API key is present but scanning is explicitly disabled "
                "via MCP_SCANNER_VIRUSTOTAL_ENABLED=false"
            )
        elif self.api_key and self.enabled:
            logger.info(
                "VirusTotal scanning enabled (API key length: %d, max_files: %s)",
                len(self.api_key),
                self.max_files if self.max_files > 0 else "unlimited",
            )
        elif not self.api_key:
            logger.debug(
                "VirusTotal scanning disabled (no API key configured). "
                "Set VIRUSTOTAL_API_KEY to enable malware scanning."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_file(self, file_path: str) -> Optional[SecurityFinding]:
        """
        Scan a single file: hash lookup first, upload if not found and enabled.

        Args:
            file_path: Absolute or relative path to the file.

        Returns:
            SecurityFinding if malicious, None otherwise.
        """
        if not self.enabled:
            return None

        path = Path(file_path)
        if not path.is_file():
            logger.warning("File does not exist: %s", file_path)
            return None

        try:
            file_hash = self._calculate_sha256(path)
            logger.info("Checking file: %s (SHA256: %s)", file_path, file_hash)

            vt_result, hash_found, error_reason = self._query_virustotal(file_hash)

            if error_reason:
                logger.warning(
                    "VirusTotal lookup failed for %s: %s", file_path, error_reason
                )
                return None

            if hash_found:
                if vt_result.get("malicious", 0) > 0:
                    return self._create_finding(
                        file_path=file_path,
                        file_hash=file_hash,
                        vt_result=vt_result,
                    )
                logger.info(
                    "File is clean: %s (%d/%d vendors)",
                    file_path,
                    vt_result.get("malicious", 0),
                    vt_result.get("total_engines", 0),
                )
                return None

            # Hash not found — upload if enabled
            if self.upload_files:
                logger.info(
                    "Hash not found in VT — uploading %s for analysis", file_path
                )
                vt_result = self._upload_and_scan(path, file_hash)
                if vt_result and vt_result.get("malicious", 0) > 0:
                    return self._create_finding(
                        file_path=file_path,
                        file_hash=file_hash,
                        vt_result=vt_result,
                    )
            else:
                logger.info(
                    "Hash not found in VT (upload disabled): %s", file_path
                )

        except Exception as e:
            logger.warning("VirusTotal scan failed for %s: %s", file_path, e)

        return None

    def analyze_directory(self, directory: str) -> List[SecurityFinding]:
        """
        Scan files in a directory using VirusTotal.

        Applies inclusion/exclusion extension filtering.
        Respects the configurable max_files limit.

        Args:
            directory: Directory path containing files to scan.

        Returns:
            List of SecurityFinding objects for malicious files detected.
        """
        if not self.enabled:
            return []

        all_files = self._discover_files(directory)
        scannable = [f for f in all_files if self._should_scan_file(f)]

        if not scannable:
            logger.debug("No scannable files found in %s", directory)
            return []

        # Enforce file limit
        total_found = len(scannable)
        if self.max_files > 0 and total_found > self.max_files:
            logger.warning(
                "Found %d scannable files but max_files limit is %d. "
                "Only the first %d files will be scanned. "
                "Set MCP_SCANNER_VT_MAX_FILES=0 for unlimited or increase the limit.",
                total_found,
                self.max_files,
                self.max_files,
            )
            skipped_files = scannable[self.max_files:]
            scannable = scannable[:self.max_files]
        else:
            skipped_files = []

        logger.info(
            "Scanning %d file(s) with VirusTotal in %s",
            len(scannable),
            directory,
        )

        findings = []
        validated_files = []

        # Scan counters
        count_scanned = 0
        count_clean = 0
        count_malicious = 0
        count_not_found = 0
        count_throttled = 0
        count_failed = 0
        count_skipped_limit = len(skipped_files)
        stop_scanning = False

        for file_path_str in scannable:
            if stop_scanning:
                count_throttled += 1
                continue

            try:
                file_path = Path(file_path_str)
                file_hash = self._calculate_sha256(file_path)
                relative_path = str(file_path.relative_to(directory))

                logger.info(
                    "Checking file: %s (SHA256: %s)", relative_path, file_hash
                )

                vt_result, hash_found, error_reason = self._query_virustotal(file_hash)

                # Handle rate limiting / quota — stop scanning remaining files
                if error_reason in ("rate_limit", "quota_exceeded", "auth_error"):
                    count_throttled += 1
                    stop_scanning = True
                    continue

                if error_reason:
                    count_failed += 1
                    continue

                count_scanned += 1

                if hash_found:
                    total = vt_result.get("total_engines", 0)
                    malicious = vt_result.get("malicious", 0)
                    suspicious = vt_result.get("suspicious", 0)

                    if malicious > 0 or suspicious > 0:
                        logger.warning(
                            "VT result: %d malicious, %d suspicious out of %d vendors — %s",
                            malicious,
                            suspicious,
                            total,
                            relative_path,
                        )
                    else:
                        logger.info(
                            "VT result: clean (%d/%d vendors) — %s",
                            malicious,
                            total,
                            relative_path,
                        )
                        validated_files.append(relative_path)
                        count_clean += 1

                    if malicious > 0:
                        finding = self._create_finding(
                            file_path=relative_path,
                            file_hash=file_hash,
                            vt_result=vt_result,
                        )
                        findings.append(finding)
                        count_malicious += 1

                elif self.upload_files:
                    logger.info(
                        "Hash not found — uploading %s for analysis", relative_path
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
                            count_malicious += 1
                        else:
                            validated_files.append(relative_path)
                            count_clean += 1
                    else:
                        count_failed += 1
                else:
                    count_not_found += 1
                    logger.info(
                        "Hash not found in VT (upload disabled): %s", relative_path
                    )

            except Exception as e:
                logger.warning(
                    "VirusTotal scan failed for %s: %s", file_path_str, e
                )
                count_failed += 1
                continue

        # Log scan summary
        total_to_scan = len(scannable)
        logger.info(
            "VirusTotal scan summary: %d/%d files scanned "
            "(%d clean, %d malicious, %d not in VT, %d throttled, %d failed"
            "%s)",
            count_scanned,
            total_to_scan,
            count_clean,
            count_malicious,
            count_not_found,
            count_throttled,
            count_failed,
            f", {count_skipped_limit} skipped by limit"
            if count_skipped_limit > 0
            else "",
        )
        if count_throttled > 0:
            logger.warning(
                "VirusTotal rate/quota limit hit: %d of %d files could not be scanned. "
                "Free tier: 4 requests/min, 500 requests/day. "
                "Consider upgrading your API key or reducing MCP_SCANNER_VT_MAX_FILES.",
                count_throttled,
                total_to_scan,
            )

        self.validated_files = validated_files
        self.last_scan_summary = {
            "total_found": total_found,
            "total_to_scan": total_to_scan,
            "scanned": count_scanned,
            "clean": count_clean,
            "malicious": count_malicious,
            "not_found": count_not_found,
            "throttled": count_throttled,
            "failed": count_failed,
            "skipped_by_limit": count_skipped_limit,
        }
        return findings

    # ------------------------------------------------------------------
    # File selection
    # ------------------------------------------------------------------

    def _discover_files(self, directory: str) -> List[str]:
        """
        Discover all files in a directory, skipping __pycache__ and hidden dirs.

        Args:
            directory: Directory path to search.

        Returns:
            Sorted list of absolute file paths.
        """
        files = []
        path = Path(directory)

        for file_path in path.rglob("*"):
            if file_path.is_file():
                if "__pycache__" not in str(file_path) and not any(
                    part.startswith(".") for part in file_path.parts
                ):
                    files.append(str(file_path))

        return sorted(files)

    def _should_scan_file(self, file_path: str) -> bool:
        """
        Determine if a file should be scanned using extension-based filtering:

          1. Extension in exclusion list → skip.
          2. Extension in inclusion list → scan.
          3. Unknown extension → skip (not in either list).

        Args:
            file_path: Path to the file.

        Returns:
            True if the file should be scanned.
        """
        ext = Path(file_path).suffix.lower()

        # Step 1: exclusion list (fast path — skip known text/code)
        if ext in self.exclusion_extensions:
            return False

        # Step 2: inclusion list (scan known binary formats)
        if ext in self.inclusion_extensions:
            return True

        # Unknown extension — skip
        return False

    # ------------------------------------------------------------------
    # VirusTotal API
    # ------------------------------------------------------------------

    def _calculate_sha256(self, file_path: Path) -> str:
        """
        Calculate SHA256 hash of a file.

        Args:
            file_path: Path to the file.

        Returns:
            SHA256 hash as hex string.
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
            file_hash: SHA256 hash of the file.

        Returns:
            Tuple of (detection_stats_dict_or_None, hash_found_bool, error_reason_or_None).
        """
        try:
            response = self.session.get(
                f"{self.base_url}/files/{file_hash}", timeout=10
            )

            if response.status_code == 404:
                return None, False, None

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
                return result, True, None

            if response.status_code == 429:
                logger.warning(
                    "VirusTotal API rate limit exceeded (HTTP 429). "
                    "Free tier allows 4 requests/minute and 500 requests/day. "
                    "Remaining files in this scan will be skipped."
                )
                return None, False, "rate_limit"

            if response.status_code == 204:
                logger.warning(
                    "VirusTotal API quota exceeded (HTTP 204). "
                    "Daily request limit reached. Remaining files will be skipped."
                )
                return None, False, "quota_exceeded"

            if response.status_code in (401, 403):
                logger.error(
                    "VirusTotal API authentication failed (HTTP %d). "
                    "Check that VIRUSTOTAL_API_KEY is valid.",
                    response.status_code,
                )
                return None, False, "auth_error"

            logger.warning(
                "VirusTotal API returned unexpected status %d for hash %s",
                response.status_code,
                file_hash,
            )
            return None, False, "api_error"

        except httpx.RequestError as e:
            logger.warning("VirusTotal API request failed: %s", e)
            return None, False, "request_error"

    def _upload_and_scan(
        self, file_path: Path, file_hash: str
    ) -> Optional[Dict[str, Any]]:
        """
        Upload file to VirusTotal for scanning and poll for results.

        Args:
            file_path: Path to the file to upload.
            file_hash: SHA256 hash of the file.

        Returns:
            Dictionary with detection stats or None if upload failed.
        """
        try:
            file_size = file_path.stat().st_size
            if file_size > 32 * 1024 * 1024:
                logger.warning(
                    "File too large to upload to VT (>32 MB): %s (%d bytes)",
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

            # Poll for completion
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
                        result, _, _ = self._query_virustotal(file_hash)
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
            result, _, _ = self._query_virustotal(file_hash)
            return result

        except httpx.RequestError as e:
            logger.warning("File upload to VirusTotal failed: %s", e)
            return None
        except Exception as e:
            logger.warning("Unexpected error during file upload: %s", e)
            return None

    # ------------------------------------------------------------------
    # Finding creation
    # ------------------------------------------------------------------

    def _create_finding(
        self, file_path: str, file_hash: str, vt_result: Dict[str, Any]
    ) -> SecurityFinding:
        """
        Create a SecurityFinding for a malicious file.

        Args:
            file_path: Relative path to the file.
            file_hash: SHA256 hash of the file.
            vt_result: VirusTotal scan results.

        Returns:
            SecurityFinding object with Malware threat category.
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
                    "Files flagged by multiple antivirus engines should not be included."
                ),
                # MCP Taxonomy details
                "aitech": threat_info["aitech"],
                "aitech_name": threat_info["aitech_name"],
                "aisubtech": threat_info["aisubtech"],
                "aisubtech_name": threat_info["aisubtech_name"],
                "taxonomy_description": threat_info["description"],
            },
        )
