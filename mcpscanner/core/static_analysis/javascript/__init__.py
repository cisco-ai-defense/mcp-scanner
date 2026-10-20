# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""JavaScript / TypeScript static-analysis package.

Provides tree-sitter-backed function-context extraction for npm MCP servers so
the language-agnostic :class:`mcpscanner.core.analyzers.behavioral.alignment.
AlignmentOrchestrator` can run the same docstring-vs-behaviour alignment
check it runs on Python sources.
"""

from .js_context_extractor import JSContextExtractor

__all__ = ["JSContextExtractor"]
