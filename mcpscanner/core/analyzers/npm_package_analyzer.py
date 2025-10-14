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

"""NPM Package Analyzer for MCP Servers.

This analyzer downloads and scans NPM packages for MCP server vulnerabilities.
"""

import asyncio
import logging
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ...config.config import Config
from .base import BaseAnalyzer, SecurityFinding
from .code_llm_analyzer import CodeLLMAnalyzer

logger = logging.getLogger(__name__)


class NPMPackageAnalyzer(BaseAnalyzer):
    """Analyzer for scanning NPM packages containing MCP servers."""

    def __init__(self, config: Config):
        """Initialize the NPM Package analyzer.
        
        Args:
            config: Configuration object with LLM settings
        """
        super().__init__("NPMPackageAnalyzer")
        self.description = "Scans NPM packages for MCP server vulnerabilities"
        self.config = config
        self.code_analyzer = CodeLLMAnalyzer(config)

    def _download_npm_package(
        self, package_name: str, version: Optional[str] = None, target_dir: str = None
    ) -> tuple[Dict[str, Any], str]:
        """Download an NPM package and extract it.
        
        Args:
            package_name: NPM package name (e.g., '@modelcontextprotocol/server-everything')
            version: Specific version to download (default: latest)
            target_dir: Target directory for extraction
            
        Returns:
            Tuple of (package_metadata, extracted_path)
            
        Raises:
            Exception: If download or extraction fails
        """
        # Get package metadata from NPM registry
        url = f"https://registry.npmjs.org/{package_name}"
        logger.info(f"Fetching NPM package metadata: {url}")
        
        response = requests.get(url, timeout=30)
        
        if response.status_code != 200:
            raise Exception(
                f"Failed to fetch package metadata. Status code: {response.status_code}"
            )
        
        data = response.json()
        
        if "name" not in data:
            raise Exception(f"Invalid package data for: {package_name}")
        
        # Get version
        if version is None:
            version = data.get("dist-tags", {}).get("latest")
            if not version:
                raise Exception(f"No latest version found for package: {package_name}")
        
        logger.info(f"Using version: {version}")
        
        # Get version details
        if version not in data.get("versions", {}):
            raise Exception(f"Version {version} not found for package: {package_name}")
        
        version_data = data["versions"][version]
        tarball_url = version_data.get("dist", {}).get("tarball")
        
        if not tarball_url:
            raise Exception(f"No tarball URL found for {package_name}@{version}")
        
        logger.info(f"Downloading package from: {tarball_url}")
        
        # Download tarball
        tarball_response = requests.get(tarball_url, timeout=60)
        
        if tarball_response.status_code != 200:
            raise Exception(f"Failed to download tarball. Status code: {tarball_response.status_code}")
        
        # Save and extract tarball
        if target_dir is None:
            target_dir = tempfile.mkdtemp(prefix="mcp_scanner_npm_")
        
        tarball_path = os.path.join(target_dir, f"{package_name.replace('/', '-')}.tgz")
        
        with open(tarball_path, 'wb') as f:
            f.write(tarball_response.content)
        
        # Extract tarball
        extract_dir = os.path.join(target_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        with tarfile.open(tarball_path, 'r:gz') as tar:
            tar.extractall(extract_dir)
        
        # NPM packages extract to a 'package' subdirectory
        package_dir = os.path.join(extract_dir, "package")
        
        if not os.path.exists(package_dir):
            # Try without 'package' subdirectory
            package_dir = extract_dir
        
        logger.info(f"Package extracted to: {package_dir}")
        
        return data, package_dir

    async def analyze(
        self,
        content: str,
        context: Optional[Dict] = None,
        http_headers: Optional[Dict] = None,
    ) -> List[SecurityFinding]:
        """Analyze an NPM package for MCP server vulnerabilities.
        
        Args:
            content: NPM package name (e.g., '@modelcontextprotocol/server-everything')
            context: Optional context with 'version' key
            http_headers: Optional HTTP headers (not used)
            
        Returns:
            List of security findings
        """
        package_name = content.strip()
        version = context.get("version") if context else None
        
        findings = []
        temp_dir = None
        
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix="mcp_scanner_npm_")
            
            # Download and extract package
            logger.info(f"Starting NPM package scan: {package_name}")
            package_data, extracted_path = self._download_npm_package(
                package_name, version, temp_dir
            )
            
            # Log package info (don't add as finding)
            version_used = version or package_data.get("dist-tags", {}).get("latest", "unknown")
            logger.info(f"Package: {package_name}@{version_used}")
            logger.info(f"Description: {package_data.get('description', 'N/A')}")
            
            # Scan the extracted package directory for TypeScript/JavaScript files
            logger.info(f"Scanning extracted package at: {extracted_path}")
            
            # Count files
            ts_files = list(Path(extracted_path).rglob("*.ts"))
            js_files = list(Path(extracted_path).rglob("*.js"))
            total_files = len(ts_files) + len(js_files)
            
            logger.info(f"Found {len(ts_files)} TypeScript files and {len(js_files)} JavaScript files")
            
            if total_files == 0:
                findings.append(
                    SecurityFinding(
                        severity="info",
                        summary="No TypeScript/JavaScript files found",
                        threat_category="Package Structure",
                        details="The package does not contain any .ts or .js files to analyze.",
                        analyzer="NPMPackageAnalyzer",
                    )
                )
                return findings
            
            # Use CodeLLMAnalyzer to scan the directory
            # Create a temporary "repo URL" that points to the local directory
            # We'll need to modify CodeLLMAnalyzer to support local directory scanning
            # For now, we'll scan files directly
            
            from .code_llm_analyzer import SupportedLanguage, MCPFunction
            
            all_functions = []
            files_scanned = 0
            
            # Scan TypeScript files
            for file_path in ts_files:
                # Skip node_modules, test files, etc. (but include dist/build for compiled packages)
                if any(skip in file_path.parts for skip in [
                    "node_modules", "test", "tests", "__tests__", ".git"
                ]):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_content = f.read()
                    
                    files_scanned += 1
                    
                    # Extract MCP functions
                    functions = self.code_analyzer._extract_mcp_functions(
                        file_content,
                        str(file_path.relative_to(extracted_path)),
                        SupportedLanguage.TYPESCRIPT
                    )
                    
                    if functions:
                        logger.info(f"Found {len(functions)} MCP functions in {file_path.name}")
                        all_functions.extend(functions)
                
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
            
            # Scan JavaScript files
            for file_path in js_files:
                # Skip node_modules, test files, etc. (but include dist/build for compiled packages)
                if any(skip in file_path.parts for skip in [
                    "node_modules", "test", "tests", "__tests__", ".git"
                ]):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_content = f.read()
                    
                    files_scanned += 1
                    
                    # Extract MCP functions (treat JS as TypeScript for pattern matching)
                    functions = self.code_analyzer._extract_mcp_functions(
                        file_content,
                        str(file_path.relative_to(extracted_path)),
                        SupportedLanguage.TYPESCRIPT
                    )
                    
                    if functions:
                        logger.info(f"Found {len(functions)} MCP functions in {file_path.name}")
                        all_functions.extend(functions)
                
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
            
            logger.info(f"Scan complete: Scanned {files_scanned} files, found {len(all_functions)} MCP functions")
            
            if len(all_functions) == 0:
                findings.append(
                    SecurityFinding(
                        severity="info",
                        summary="No MCP functions found",
                        threat_category="Package Analysis",
                        details=f"Scanned {files_scanned} files but found no MCP server functions. "
                               f"This analyzer looks for server.tool(), server.registerTool(), etc.",
                        analyzer="NPMPackageAnalyzer",
                    )
                )
                return findings
            
            # Analyze each function with LLM
            if self.code_analyzer.llm_enabled:
                for mcp_func in all_functions:
                    func_findings = await self.code_analyzer._analyze_function_with_llm(mcp_func)
                    findings.extend(func_findings)
            else:
                findings.append(
                    SecurityFinding(
                        severity="info",
                        summary=f"Found {len(all_functions)} MCP functions (LLM analysis disabled)",
                        threat_category="Package Analysis",
                        details=f"Extracted {len(all_functions)} MCP functions but LLM analysis is not enabled. "
                               f"Configure LLM settings to perform vulnerability analysis.",
                        analyzer="NPMPackageAnalyzer",
                    )
                )
            
            # Log summary (don't add as finding - it's redundant)
            vuln_count = len([f for f in findings if f.severity in ['high', 'medium', 'low']])
            logger.info(f"Analysis complete: {files_scanned} files scanned, {len(all_functions)} MCP functions found, {vuln_count} vulnerabilities detected")
        
        except Exception as e:
            logger.error(f"Error analyzing NPM package {package_name}: {e}")
            findings.append(
                SecurityFinding(
                    severity="info",
                    summary=f"Error analyzing package: {package_name}",
                    threat_category="Error",
                    details=f"Failed to analyze package: {str(e)}",
                    analyzer="NPMPackageAnalyzer",
                )
            )
        
        finally:
            # Cleanup temporary directory
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup temporary directory {temp_dir}: {e}")
        
        return findings
