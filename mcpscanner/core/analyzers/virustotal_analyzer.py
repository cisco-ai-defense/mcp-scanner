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

Three-tier file selection:
  1. **Known text** (.md, .json, .yaml, …) → verify with magic bytes first.
     Skip only if magic bytes confirm text; scan if magic says otherwise.
  2. **Known dangerous** (scripts, executables, archives, macro docs, …
     sourced from filesec.io) → always scan.
  3. **Unknown / extensionless** → magic-byte check; scan if non-text.

Dependencies:
  - ``httpx`` – sync HTTP client (already a project dependency)
  - ``puremagic`` – optional, for magic-byte checks

Integration point: Registered as a main analyzer alongside YARA, LLM, etc.
"""

import hashlib
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from ...threats.threats import ThreatMapping
from .base import SecurityFinding
from ...utils.file_magic import detect_magic

logger = logging.getLogger(__name__)

# =========================================================================
# Extension classification sets (Section 2.1 of design doc)
# =========================================================================

# Extensions that are CONFIRMED plain text / data only.
# NOT executable, NOT macro-capable, NOT used in attacker toolchains.
# NOTE: .html, .htm, .svg, .xml are intentionally EXCLUDED from this set
#       because they can carry scripts, phishing, and embedded content
#       (see https://filesec.io/).
_PURE_TEXT_EXTENSIONS: Set[str] = {
    ".md", ".txt", ".rst", ".adoc", ".org", ".tex",     # prose
    ".json", ".yaml", ".yml", ".toml", ".ini",           # config/data
    ".cfg", ".conf", ".csv", ".tsv",                     # config/data
    ".css", ".scss", ".sass", ".less",                   # stylesheets (no script)
    ".graphql", ".proto", ".thrift",                     # schema
    ".gitignore", ".gitattributes", ".editorconfig",     # dotfiles (config only)
    ".env.example", ".dockerignore",                     # templates
    ".lock",                                             # lockfiles
}

# Families that are never directly executable / malware carriers.
# If magic bytes confirm the family matches, skip VT lookup.
_TEXT_ONLY_FAMILIES: Set[str] = {"text"}

# -----------------------------------------------------------------------
# Known dangerous extensions — sourced from https://filesec.io/ +
# standard binary/script formats.
# -----------------------------------------------------------------------

# Script & executable code (cross-platform)
_KNOWN_DANGEROUS_SCRIPT: Set[str] = {
    ".py", ".pyc", ".pyo", ".pyw", ".pyz", ".pyzw",     # Python (filesec.io)
    ".js", ".jse", ".ts", ".jsx", ".tsx", ".mjs",        # JavaScript / JScript
    ".sh", ".bash", ".zsh", ".fish",                     # Unix shell
    ".ps1", ".bat", ".cmd",                              # Windows shell (filesec.io)
    ".vb", ".vbs", ".vbe",                               # VBScript (filesec.io)
    ".ws", ".wsf", ".wsh",                               # Windows Script Host (filesec.io)
    ".hta",                                              # HTML Application (filesec.io)
    ".sct",                                              # Scriptlet (filesec.io)
    ".xsl",                                              # XSLT (filesec.io)
    ".mof",                                              # Managed Object Format (filesec.io)
    ".a3x",                                              # AutoIt compiled (filesec.io)
    ".applescript", ".scpt",                             # macOS scripts (filesec.io)
    ".service", ".timer",                                # systemd units (filesec.io)
    ".rb", ".pl", ".php",                                # Server-side scripting
    ".java", ".kt", ".cs", ".go", ".rs",                 # Compiled languages (source)
    ".c", ".cpp", ".h", ".hpp", ".swift",                # Compiled languages (source)
}

# Native executables & libraries
_KNOWN_DANGEROUS_EXECUTABLE: Set[str] = {
    ".exe", ".dll", ".so", ".dylib", ".com",             # Standard binaries (filesec.io)
    ".bin", ".ocx", ".cpl",                              # Windows executables (filesec.io)
    ".scr", ".pif",                                      # Screensaver / PIF (filesec.io)
    ".msi", ".msp", ".msix",                             # Windows installers (filesec.io)
    ".appx", ".appxbundle", ".appinstaller",             # Windows app packages (filesec.io)
    ".application", ".appref-ms",                        # ClickOnce (filesec.io)
    ".gadget", ".ppkg",                                  # Windows gadgets/provisioning (filesec.io)
    ".dmg", ".pkg",                                      # macOS installers (filesec.io)
    ".deb", ".rpm", ".snap", ".flatpak",                 # Linux packages
    ".apk", ".ipa", ".aab",                              # Mobile packages
    ".wasm",                                             # WebAssembly
    ".class", ".jar", ".war", ".ear", ".jnlp",          # Java (filesec.io)
}

# Archives & disk images
_KNOWN_DANGEROUS_ARCHIVE: Set[str] = {
    ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2",       # Common archives (filesec.io)
    ".xz", ".z", ".tgz", ".lz", ".lzma", ".zst",        # Compression
    ".cab", ".arj", ".uue",                              # Legacy archives (filesec.io)
    ".iso", ".img", ".dmg", ".daa",                      # Disk images (filesec.io)
    ".vhd", ".vhdx", ".wim",                             # Virtual disks (filesec.io)
}

# Documents with macro / embedded content capability
_KNOWN_DANGEROUS_DOCUMENT: Set[str] = {
    # Office with macros (filesec.io)
    ".doc", ".docm", ".dot", ".dotm",                    # Word
    ".xls", ".xlsm", ".xlsb", ".xlam", ".xll",          # Excel (filesec.io)
    ".xlt", ".xltm", ".xlm", ".slk",                    # Excel templates/macros
    ".ppt", ".pptm", ".pps", ".ppsm",                   # PowerPoint (filesec.io)
    ".pot", ".potm", ".sldm",                            # PowerPoint templates
    ".pub", ".wbk", ".wiz", ".asd",                      # Other Office (filesec.io)
    ".ppa", ".ppam",                                     # PowerPoint add-ins (filesec.io)
    # Office without macros (still archive-based, can embed OLE)
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    # Other document formats
    ".pdf", ".rtf",                                      # (filesec.io)
    ".chm",                                              # Compiled HTML Help (filesec.io)
    ".hwpx",                                             # Hancom (filesec.io)
}

# Web / phishing vectors that can carry scripts or redirect
_KNOWN_DANGEROUS_WEB: Set[str] = {
    ".html", ".htm", ".mht", ".mhtml",                   # (filesec.io)
    ".svg",                                              # (filesec.io -- script/phishing)
    ".xml",                                              # Can contain XSLT/entities
    ".eml",                                              # Email (filesec.io)
    ".ics",                                              # Calendar invite (filesec.io)
    ".url", ".website",                                  # URL shortcuts (filesec.io)
    ".lnk",                                              # Windows shortcut (filesec.io)
    ".scf",                                              # Shell Command File (filesec.io)
    ".iqy",                                              # Excel Web Query (filesec.io)
}

# Windows-specific system files used in attacks
_KNOWN_DANGEROUS_WINDOWS: Set[str] = {
    ".reg",                                              # Registry (filesec.io)
    ".msc",                                              # MMC snap-in (filesec.io)
    ".diagcab",                                          # Diagnostic (filesec.io)
    ".settingcontent-ms",                                # (filesec.io)
    ".library-ms", ".searchConnector-ms",                # (filesec.io)
    ".desktopthemepackfile", ".theme", ".themepack",     # (filesec.io)
    ".msrcincident",                                     # (filesec.io)
    ".oxps", ".xps",                                     # XPS documents (filesec.io)
    ".bgi",                                              # BGInfo (filesec.io)
    ".mam",                                              # Access macro (filesec.io)
}

# Font files (can contain exploitable parsers)
_KNOWN_DANGEROUS_FONT: Set[str] = {
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
}

# Union for reference / test assertions
_ALL_KNOWN_DANGEROUS: Set[str] = (
    _KNOWN_DANGEROUS_SCRIPT
    | _KNOWN_DANGEROUS_EXECUTABLE
    | _KNOWN_DANGEROUS_ARCHIVE
    | _KNOWN_DANGEROUS_DOCUMENT
    | _KNOWN_DANGEROUS_WEB
    | _KNOWN_DANGEROUS_WINDOWS
    | _KNOWN_DANGEROUS_FONT
)

# =========================================================================
# Rate-limit constants (VT free tier)
# =========================================================================

_VT_REQUESTS_PER_MINUTE = 4
_VT_DAILY_CAP = 500


# =========================================================================
# Analyzer
# =========================================================================

class VirusTotalAnalyzer:
    """
    Analyzer that checks files against VirusTotal using hash lookups and uploads.

    Three-tier file selection:
      1. Pure text extension → verify with magic bytes, skip if confirmed text.
      2. Known dangerous extension → always scan.
      3. Unknown / no extension → magic-byte check, scan if non-text.
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
            inclusion_extensions: Extra binary extensions to always include.
            exclusion_extensions: Extra text extensions to always exclude.
        """
        self.api_key = api_key
        self.enabled = enabled and api_key is not None
        self.upload_files = upload_files
        self.max_files = max_files
        # Merge caller-provided sets with the built-in classification
        self._extra_inclusion = inclusion_extensions or set()
        self._extra_exclusion = exclusion_extensions or set()
        self.validated_files: List[str] = []
        self.last_scan_summary: Dict[str, int] = {}
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = httpx.Client()

        # Hash cache: sha256 → (result_dict | None, hash_found)
        self._hash_cache: Dict[str, Tuple[Optional[Dict[str, Any]], bool]] = {}

        # Rate-limit tracking
        self._api_calls: int = 0
        self._minute_window_start: float = 0.0
        self._minute_calls: int = 0

        if self.api_key:
            self.session.headers.update(
                {"x-apikey": self.api_key, "Accept": "application/json"}
            )

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

            vt_result, hash_found, error_reason = self._query_virustotal_cached(
                file_hash
            )

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

        Applies three-tier file selection, respects max_files limit,
        and enforces per-minute / daily rate limits.

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
            skipped_files = scannable[self.max_files :]
            scannable = scannable[: self.max_files]
        else:
            skipped_files = []

        logger.info(
            "Scanning %d file(s) with VirusTotal in %s",
            len(scannable),
            directory,
        )

        findings: List[SecurityFinding] = []
        validated_files: List[str] = []

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

                vt_result, hash_found, error_reason = (
                    self._query_virustotal_cached(file_hash)
                )

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
    # Three-tier file selection (Section 2.2 of design doc)
    # ------------------------------------------------------------------

    def _should_scan_file(self, file_path: str) -> bool:
        """
        Three-tier file selection:

          1. ext in _PURE_TEXT_EXTENSIONS → verify with magic bytes.
             Skip only if magic confirms text; scan if magic disagrees.
          2. ext in _ALL_KNOWN_DANGEROUS → always scan.
          3. No extension / unknown extension → magic-byte check.
             Scan if magic says non-text, skip otherwise.

        Args:
            file_path: Path to the file.

        Returns:
            True if the file should be scanned with VirusTotal.
        """
        ext = Path(file_path).suffix.lower()

        # Also honour any caller-provided exclusion overrides
        combined_text = _PURE_TEXT_EXTENSIONS | self._extra_exclusion

        # Step 1: Pure text extension — verify with magic bytes
        if ext in combined_text:
            if self._magic_says_not_text(file_path):
                logger.warning(
                    "Extension mismatch: %s claims text but magic bytes disagree — scanning",
                    file_path,
                )
                return True
            return False

        # Step 2: Known dangerous extension — always scan
        combined_dangerous = _ALL_KNOWN_DANGEROUS | self._extra_inclusion
        if ext in combined_dangerous:
            return True

        # Step 3: No extension
        if not ext:
            if self._magic_says_not_text(file_path):
                return True
            return False

        # Step 4: Unknown extension — fall back to magic bytes
        if self._magic_says_not_text(file_path):
            return True
        return False

    def _magic_says_not_text(self, file_path: str) -> bool:
        """
        Check if magic bytes indicate the file is NOT text.

        Returns:
            True  → magic says non-text (scan it).
            False → magic says text, no signature, or puremagic unavailable.
        """
        try:
            result = detect_magic(file_path)
            if result is None:
                return False  # No signature found → likely text
            if result.content_family in _TEXT_ONLY_FAMILIES:
                return False  # Confirmed text
            return True  # Magic disagrees — non-text content
        except Exception:
            return False  # Fail open — trust the extension

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _discover_files(self, directory: str) -> List[str]:
        """
        Discover all files in a directory, skipping __pycache__ and hidden dirs.

        Args:
            directory: Directory path to search.

        Returns:
            Sorted list of absolute file paths.
        """
        files: List[str] = []
        path = Path(directory)

        for file_path in path.rglob("*"):
            if file_path.is_file():
                if "__pycache__" not in str(file_path) and not any(
                    part.startswith(".") for part in file_path.parts
                ):
                    files.append(str(file_path))

        return sorted(files)

    # ------------------------------------------------------------------
    # VirusTotal API (with hash caching and rate limiting)
    # ------------------------------------------------------------------

    def _calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _query_virustotal_cached(
        self, file_hash: str
    ) -> Tuple[Optional[Dict[str, Any]], bool, Optional[str]]:
        """
        Query VT with in-memory hash cache to avoid duplicate lookups.

        Returns:
            (result_dict | None, hash_found, error_reason | None)
        """
        if file_hash in self._hash_cache:
            cached_result, cached_found = self._hash_cache[file_hash]
            logger.debug("Cache hit for hash %s (found=%s)", file_hash, cached_found)
            return cached_result, cached_found, None

        # Enforce rate limits before making the API call
        self._enforce_rate_limit()

        result, found, error = self._query_virustotal(file_hash)

        # Cache successful lookups (don't cache errors)
        if error is None:
            self._hash_cache[file_hash] = (result, found)

        return result, found, error

    def _enforce_rate_limit(self) -> None:
        """
        Enforce VT free-tier rate limits:
          - 4 requests per minute
          - 500 requests per day
        """
        now = time.monotonic()

        # Daily cap
        if self._api_calls >= _VT_DAILY_CAP:
            logger.warning(
                "VirusTotal daily cap reached (%d requests). "
                "Remaining files will be skipped.",
                _VT_DAILY_CAP,
            )
            return

        # Per-minute window
        if now - self._minute_window_start >= 60:
            self._minute_window_start = now
            self._minute_calls = 0

        if self._minute_calls >= _VT_REQUESTS_PER_MINUTE:
            wait = 60 - (now - self._minute_window_start)
            if wait > 0:
                logger.info(
                    "Rate limit: waiting %.1fs before next VT request "
                    "(4 req/min free tier)",
                    wait,
                )
                time.sleep(wait)
            self._minute_window_start = time.monotonic()
            self._minute_calls = 0

        self._api_calls += 1
        self._minute_calls += 1

    def _query_virustotal(
        self, file_hash: str
    ) -> Tuple[Optional[Dict[str, Any]], bool, Optional[str]]:
        """
        Query VirusTotal API for file hash.

        Returns:
            (detection_stats_dict | None, hash_found, error_reason | None)
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

            self._enforce_rate_limit()

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
                self._enforce_rate_limit()

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

        Severity: HIGH if detection ratio >= 0.1, MEDIUM otherwise.
        """
        malicious_count = vt_result.get("malicious", 0)
        total_engines = vt_result.get("total_engines", 0)

        if total_engines > 0:
            detection_ratio = malicious_count / total_engines
            severity = "HIGH" if detection_ratio >= 0.1 else "MEDIUM"
        else:
            severity = "MEDIUM"

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
