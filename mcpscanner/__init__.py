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

"""MCP Scanner SDK.

A Python SDK for scanning MCP servers and tools for security findings.
Provides both a programmatic API and a REST API server.
"""

from .core.analyzers.api_analyzer import ApiAnalyzer
from .core.analyzers.base import BaseAnalyzer, SecurityFinding
from .core.analyzers.llm_analyzer import LLMAnalyzer
from .core.analyzers.yara_analyzer import YaraAnalyzer
from .core.auth import (
    InMemoryTokenStorage,
    OAuthHandler,
    create_oauth_provider_from_config,
    Auth,
    AuthType,
)
from .core.exceptions import (
    MCPScannerError,
    MCPConnectionError,
    MCPAuthenticationError,
    MCPServerNotFoundError,
)
from .api.api import app as api_app
from .api.router import get_scanner, router
from .config.config import Config
from .core.scanner import Scanner, ScannerFactory
from .core.result import ScanResult, ToolScanResult, PromptScanResult, ResourceScanResult
from .core.models import AnalyzerEnum

__all__ = [
    "Config",
    "BaseAnalyzer",
    "SecurityFinding",
    "ApiAnalyzer",
    "YaraAnalyzer",
    "LLMAnalyzer",
    "Scanner",
    "ScannerFactory",
    "ScanResult",
    "ToolScanResult",
    "PromptScanResult",
    "ResourceScanResult",
    "Auth",
    "AuthType",
    "InMemoryTokenStorage",
    "OAuthHandler",
    "create_oauth_provider_from_config",
    "MCPScannerError",
    "MCPConnectionError",
    "MCPAuthenticationError",
    "MCPServerNotFoundError",
    "api_app",
    "AnalyzerEnum",
    "get_scanner",
    "router",
]
