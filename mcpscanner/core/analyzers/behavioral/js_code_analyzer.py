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

"""JavaScript / TypeScript behavioral analyzer (delegates to BehavioralCodeAnalyzer)."""

from __future__ import annotations

from ....config.config import Config
from .code_analyzer import BehavioralCodeAnalyzer

# Source extensions we treat as JS/TS. Keep in sync with
# ``NativeAnalyzer`` / ``BehavioralCodeAnalyzer`` path handling.
_JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")

# Directories we never recurse into during npm scans.
_SKIP_DIRS = frozenset(
    {"node_modules", "dist", "build", "out", ".git", ".next", ".turbo", "coverage"}
)


class JSBehavioralCodeAnalyzer(BehavioralCodeAnalyzer):
    """Backward-compatible JS/TS entry point.

    npm and Docker npm entrypoints import this class; it now runs the full
    multi-language :class:`BehavioralCodeAnalyzer` pipeline (JSContextExtractor
    merge, code graph, SAFE synthesis, cross-file enrich).
    """

    def __init__(self, config: Config):
        super().__init__(config)
        self.name = "Behavioural (JS)"
