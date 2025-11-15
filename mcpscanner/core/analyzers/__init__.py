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

"""Analyzers package for MCP Scanner

This package contains different analyzers for scanning MCP tools:
- Pattern-based analyzers (YARA, API)
- LLM-based semantic analyzers
- Behavioral code analyzers (static analysis + semantic alignment)
"""

from .api_analyzer import ApiAnalyzer
from .base import BaseAnalyzer, SecurityFinding
from .behavioral import BehavioralCodeAnalyzer, AlignmentOrchestrator
from .llm_analyzer import LLMAnalyzer
from .yara_analyzer import YaraAnalyzer

__all__ = [
    "BaseAnalyzer",
    "SecurityFinding",
    "ApiAnalyzer",
    "YaraAnalyzer",
    "LLMAnalyzer",
    "BehavioralCodeAnalyzer",
    "AlignmentOrchestrator",
]
