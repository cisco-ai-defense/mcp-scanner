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

"""Core scanning functionality for MCP Scanner."""

from .analyzers.api_analyzer import ApiAnalyzer
from .analyzers.base import BaseAnalyzer, SecurityFinding
from .analyzers.llm_analyzer import LLMAnalyzer
from .analyzers.yara_analyzer import YaraAnalyzer
from .models import ScanRequest
from mcp.types import Tool as MCPTool
from .npm_scanner import NPMPackageScanner, NPMScanError
from .package_sandbox import (
    PackageDownloadError,
    PackageExtractionError,
    PackageIntegrityError,
)
from .pypi_scanner import (
    DockerNotAvailableError,
    LLMNotConfiguredError,
    PyPIPackageScanner,
    PyPIScanError,
    analysis_scan_status,
)
from .result import ScanResult
from .scanner import Scanner

__all__ = [
    "BaseAnalyzer",
    "SecurityFinding",
    "ApiAnalyzer",
    "YaraAnalyzer",
    "LLMAnalyzer",
    "MCPTool",
    "ScanRequest",
    "ScanResult",
    "Scanner",
    "PyPIPackageScanner",
    "PyPIScanError",
    "NPMPackageScanner",
    "NPMScanError",
    "DockerNotAvailableError",
    "LLMNotConfiguredError",
    "PackageDownloadError",
    "PackageExtractionError",
    "PackageIntegrityError",
    "analysis_scan_status",
]
