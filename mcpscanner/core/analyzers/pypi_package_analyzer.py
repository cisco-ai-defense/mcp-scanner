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

"""PyPI Package Analyzer for MCP Scanner.

This analyzer downloads PyPI packages and scans their source code for security 
vulnerabilities using LLM-based code analysis. It focuses on detecting:
- Remote Code Execution (RCE)
- Command Injection
- SQL/NoSQL Injection
- Data Exfiltration
- Other code-level security issues
"""

import logging
import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import tarsafe  # type: ignore
    TARSAFE_AVAILABLE = True
except ImportError:
    TARSAFE_AVAILABLE = False

from ...config.config import Config
from .base import BaseAnalyzer, SecurityFinding
from .code_llm_analyzer import CodeLLMAnalyzer, SupportedLanguage

logger = logging.getLogger(__name__)


class PyPIPackageAnalyzer(BaseAnalyzer):
    """Analyzer for scanning PyPI packages using LLM-based code analysis.
    
    This analyzer:
    1. Downloads packages from PyPI
    2. Safely extracts the source code
    3. Scans Python files for MCP functions
    4. Analyzes code for security vulnerabilities using LLM
    """

    def __init__(self, config: Config):
        """Initialize the PyPI Package analyzer.
        
        Args:
            config: Configuration object with LLM settings
        """
        super().__init__("PyPIPackageAnalyzer")
        self.description = "Downloads and scans PyPI package source code for security vulnerabilities"
        
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required for PyPI package scanning. Install with: pip install requests")
        
        if not TARSAFE_AVAILABLE:
            logger.warning("tarsafe library not available. Tar extraction may be less secure. Install with: pip install tarsafe")
        
        # Initialize Code LLM analyzer for actual scanning
        self.code_analyzer = CodeLLMAnalyzer(config)
        self.llm_enabled = self.code_analyzer.llm_enabled

    async def analyze(
        self,
        content: str,
        context: Optional[Dict] = None,
        http_headers: Optional[Dict] = None,
    ) -> List[SecurityFinding]:
        """Analyze a PyPI package for security vulnerabilities.

        Args:
            content: Package name (e.g., "requests")
            context: Optional context with 'version' key
            http_headers: Not used for PyPI scanning

        Returns:
            List of security findings
        """
        package_name = content.strip()
        version = context.get("version") if context else None
        
        logger.info(f"Starting PyPI package scan: {package_name}" + (f" version {version}" if version else ""))
        
        findings = []
        temp_dir = None
        
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix="mcp_scanner_pypi_")
            
            # Get package metadata
            metadata = self._get_package_metadata(package_name)
            
            # Determine version
            if version is None:
                version = metadata["info"]["version"]
                logger.info(f"Using latest version: {version}")
            
            # Download and extract package
            extract_path = await self._download_and_extract_package(
                package_name, version, metadata, temp_dir
            )
            
            # Scan extracted code using Code LLM analyzer
            logger.info(f"Scanning extracted package at: {extract_path}")
            code_findings = await self._scan_package_code(extract_path, package_name, version)
            findings.extend(code_findings)
            
            # Add summary finding
            if findings:
                summary_finding = SecurityFinding(
                    severity="info",
                    summary=f"PyPI package scan complete: {package_name} v{version} - {len(findings)} findings",
                    threat_category="Summary",
                    details=f"Package: {package_name}\nVersion: {version}\nTotal Findings: {len(findings)}",
                    analyzer="PyPIPackageAnalyzer",
                )
                findings.append(summary_finding)
            
        except Exception as e:
            logger.error(f"Error scanning PyPI package {package_name}: {e}")
            findings.append(
                SecurityFinding(
                    severity="high",
                    summary=f"Failed to scan PyPI package: {package_name}",
                    threat_category="Scan Error",
                    details=f"Error: {str(e)}",
                    analyzer="PyPIPackageAnalyzer",
                )
            )
        finally:
            # Cleanup temporary directory
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp directory {temp_dir}: {e}")
        
        return findings

    def _get_package_metadata(self, package_name: str) -> Dict[str, Any]:
        """Get package metadata from PyPI JSON API.
        
        Args:
            package_name: Name of the package
            
        Returns:
            Package metadata dictionary
            
        Raises:
            Exception: If package not found or API error
        """
        url = f"https://pypi.org/pypi/{package_name}/json"
        logger.debug(f"Fetching package metadata from: {url}")
        
        response = requests.get(url, timeout=30)
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch package metadata. Status code: {response.status_code}")
        
        data = response.json()
        
        if "message" in data:
            raise Exception(f"PyPI API error: {data['message']}")
        
        return data

    async def _download_and_extract_package(
        self, package_name: str, version: str, metadata: Dict, temp_dir: str
    ) -> str:
        """Download and extract a PyPI package.
        
        Args:
            package_name: Name of the package
            version: Version to download
            metadata: Package metadata from PyPI
            temp_dir: Temporary directory for extraction
            
        Returns:
            Path to extracted package directory
            
        Raises:
            Exception: If download or extraction fails
        """
        releases = metadata.get("releases", {})
        
        if version not in releases:
            raise Exception(f"Version {version} not found for package {package_name}")
        
        files = releases[version]
        
        # Find source distribution (prefer .tar.gz over .whl)
        source_dist = None
        for file_info in files:
            filename = file_info["filename"]
            if self._is_supported_archive(filename):
                # Prefer source distributions
                if filename.endswith((".tar.gz", ".tar.bz2", ".tar.xz", ".zip")):
                    source_dist = file_info
                    break
                elif not source_dist:  # Fallback to wheel
                    source_dist = file_info
        
        if not source_dist:
            raise Exception(f"No supported archive found for {package_name} v{version}")
        
        # Download package
        download_url = source_dist["url"]
        filename = source_dist["filename"]
        archive_path = os.path.join(temp_dir, filename)
        
        logger.info(f"Downloading package from: {download_url}")
        response = requests.get(download_url, stream=True, timeout=120)
        response.raise_for_status()
        
        with open(archive_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        logger.debug(f"Downloaded package to: {archive_path}")
        
        # Extract package
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        self._safe_extract(archive_path, extract_dir)
        
        # Remove archive file
        os.remove(archive_path)
        
        # Find the actual package directory (usually has version in name)
        extracted_items = os.listdir(extract_dir)
        if len(extracted_items) == 1 and os.path.isdir(os.path.join(extract_dir, extracted_items[0])):
            return os.path.join(extract_dir, extracted_items[0])
        
        return extract_dir

    def _is_supported_archive(self, filename: str) -> bool:
        """Check if file is a supported archive format.
        
        Args:
            filename: Name of the file
            
        Returns:
            True if supported, False otherwise
        """
        supported_extensions = [
            ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz",
            ".zip", ".whl", ".egg"
        ]
        return any(filename.endswith(ext) for ext in supported_extensions)

    def _safe_extract(self, archive_path: str, target_dir: str) -> None:
        """Safely extract an archive file.
        
        Args:
            archive_path: Path to archive file
            target_dir: Directory to extract to
            
        Raises:
            ValueError: If archive format is unsupported
        """
        logger.debug(f"Extracting {archive_path} to {target_dir}")
        
        # Try tarsafe first if available
        if TARSAFE_AVAILABLE and tarsafe.is_tarfile(archive_path):
            tarsafe.open(archive_path).extractall(target_dir)
            self._fix_permissions(target_dir)
            return
        
        # Fallback to tarfile for tar archives
        import tarfile
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, 'r:*') as tar:
                # Extract with path sanitization
                for member in tar.getmembers():
                    # Sanitize path to prevent directory traversal
                    member_path = os.path.normpath(member.name)
                    if member_path.startswith("..") or os.path.isabs(member_path):
                        logger.warning(f"Skipping potentially malicious path: {member.name}")
                        continue
                    tar.extract(member, target_dir)
            self._fix_permissions(target_dir)
            return
            
        # Handle zip files
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                for member in zip_ref.namelist():
                    # Sanitize path to prevent directory traversal
                    member_path = os.path.normpath(member)
                    if member_path.startswith("..") or os.path.isabs(member_path):
                        logger.warning(f"Skipping potentially malicious path: {member}")
                        continue
                    zip_ref.extract(member, target_dir)
            self._fix_permissions(target_dir)
            return
            
        raise ValueError(f"Unsupported archive format: {archive_path}")

    def _fix_permissions(self, directory: str) -> None:
        """Fix file permissions after extraction.
        
        Args:
            directory: Directory to fix permissions in
        """
        try:
            # Make directories executable and files readable
            for root, dirs, files in os.walk(directory):
                for d in dirs:
                    dir_path = os.path.join(root, d)
                    os.chmod(dir_path, os.stat(dir_path).st_mode | stat.S_IEXEC | stat.S_IREAD)
                
                for f in files:
                    file_path = os.path.join(root, f)
                    os.chmod(file_path, os.stat(file_path).st_mode | stat.S_IREAD)
        except Exception as e:
            logger.warning(f"Failed to fix permissions: {e}")

    async def _scan_package_code(
        self, package_path: str, package_name: str, version: str
    ) -> List[SecurityFinding]:
        """Scan package code using Code LLM analyzer.
        
        Args:
            package_path: Path to extracted package
            package_name: Name of the package
            version: Package version
            
        Returns:
            List of security findings
        """
        findings = []
        
        # Find all Python files
        python_files = []
        for root, _, files in os.walk(package_path):
            for file in files:
                if file.endswith(".py"):
                    python_files.append(os.path.join(root, file))
        
        logger.info(f"Found {len(python_files)} Python files to scan")
        
        # Extract and analyze MCP functions from each file
        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read()
                
                # Extract MCP functions
                relative_path = os.path.relpath(file_path, package_path)
                functions = self.code_analyzer._extract_mcp_functions(
                    file_content, relative_path, SupportedLanguage.PYTHON
                )
                
                # Analyze each function
                for func in functions:
                    func_findings = await self.code_analyzer._analyze_function_with_llm(func)
                    findings.extend(func_findings)
                    
            except Exception as e:
                logger.warning(f"Error scanning file {file_path}: {e}")
        
        return findings
