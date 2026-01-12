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

"""Static Analysis Engine for MCP Security Scanner.

This module provides comprehensive static analysis capabilities following
industry-standard SAST tool conventions:

- **Parser**: Language-specific source code parsers (Python, etc.)
- **Context Extraction**: Extract rich code context for security analysis
- **CFG**: Control Flow Graph construction
- **Dataflow**: Forward/backward dataflow analysis passes
- **Taint**: Taint tracking for security vulnerabilities
- **Interprocedural**: Cross-file call graph analysis
- **Semantic**: Name resolution and type inference

Architecture inspired by Semgrep, CodeQL, and other production SAST tools.
"""

from .context_extractor import ContextExtractor, FunctionContext

__version__ = "1.0.0"

__all__ = ["__version__", "ContextExtractor", "FunctionContext"]
