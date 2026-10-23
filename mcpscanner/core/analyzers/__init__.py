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

import importlib

from .api_analyzer import ApiAnalyzer
from .base import BaseAnalyzer, SecurityFinding
from .yara_analyzer import YaraAnalyzer
from .virustotal_analyzer import VirusTotalAnalyzer
from .prompt_defense_analyzer import PromptDefenseAnalyzer
from .vulnerable_package_analyzer import VulnerablePackageAnalyzer
from .readiness import ReadinessAnalyzer, OpaProvider
from .schema_reference_analyzer import SchemaReferenceAnalyzer

# LLM-backed analyzers import LiteLLM when constructed. Keep them off the
# import path of YARA and the other non-LLM analyzers.
_LAZY_EXPORTS = {
    "LLMAnalyzer": (".llm_analyzer", "LLMAnalyzer"),
    "MetaAnalyzer": (".meta_analyzer", "MetaAnalyzer"),
    "MetaAnalysisResult": (".meta_analyzer", "MetaAnalysisResult"),
    "apply_meta_analysis": (".meta_analyzer", "apply_meta_analysis"),
    "BehavioralCodeAnalyzer": (".behavioral", "BehavioralCodeAnalyzer"),
    "AlignmentOrchestrator": (".behavioral", "AlignmentOrchestrator"),
    "ReadinessLLMJudge": (".readiness", "ReadinessLLMJudge"),
}

__all__ = [
    "BaseAnalyzer",
    "SecurityFinding",
    "ApiAnalyzer",
    "YaraAnalyzer",
    "LLMAnalyzer",
    "MetaAnalyzer",
    "MetaAnalysisResult",
    "apply_meta_analysis",
    "BehavioralCodeAnalyzer",
    "AlignmentOrchestrator",
    "VirusTotalAnalyzer",
    "PromptDefenseAnalyzer",
    "VulnerablePackageAnalyzer",
    "ReadinessAnalyzer",
    "ReadinessLLMJudge",
    "OpaProvider",
    "SchemaReferenceAnalyzer",
]


def __getattr__(name: str):
    """Import LLM-backed analyzers only when a caller asks for them."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = target
    module = importlib.import_module(module_name, __name__)
    value = getattr(module, attr)
    globals()[name] = value
    return value
