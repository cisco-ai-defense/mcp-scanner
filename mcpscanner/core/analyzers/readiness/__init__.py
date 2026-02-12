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

"""Readiness Analyzer package for MCP Scanner.

This package contains analyzers for production readiness issues:
- Heuristic-based static analysis (default, zero-dependency)
- Optional OPA policy-based checks (requires OPA binary in PATH)
- Optional LLM-based semantic analysis (requires API key)
"""

from .readiness_analyzer import ReadinessAnalyzer
from .llm_judge import ReadinessLLMJudge
from .opa_provider import OpaProvider

__all__ = [
    "ReadinessAnalyzer",
    "ReadinessLLMJudge",
    "OpaProvider",
]
