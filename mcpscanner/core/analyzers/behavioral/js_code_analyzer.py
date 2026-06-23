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

"""Behavioral Code Analyzer for JavaScript / TypeScript MCP servers.

The orchestrator is language-agnostic — give it a ``FunctionContext`` and it
runs the same LLM-based docstring-vs-behaviour alignment check it runs on
Python. This module is the JS counterpart of
:class:`BehavioralCodeAnalyzer`: it walks ``.js``/``.ts`` sources via the
tree-sitter extractor, feeds the resulting contexts into the orchestrator,
and turns mismatches into ``SecurityFinding`` records with the same shape
the rest of the scanner consumes.

Static dataflow / taint / call-graph analysis is *not* run on JS in this
pass; the LLM sees identifiers, imports, calls, string literals, and
heuristic booleans. That's enough to surface description-vs-behaviour
mismatches; the prompt builder treats missing fields as missing evidence,
not as "clean".
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ....config.config import Config
from ....config.constants import MCPScannerConstants
from ....threats.threats import ThreatMapping
from ..base import BaseAnalyzer, SecurityFinding
from .alignment import AlignmentOrchestrator


# Source extensions we treat as JS/TS. Keep in sync with
# ``JSContextExtractor._language_for_path``.
_JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")

# Directories we never recurse into. The npm tarball never contains a
# nested ``node_modules`` for the package itself, but third-party tarballs
# sometimes do, and we don't want to analyse vendored copies of unrelated
# dependencies.
_SKIP_DIRS = frozenset(
    {"node_modules", "dist", "build", "out", ".git", ".next", ".turbo", "coverage"}
)


class JSBehavioralCodeAnalyzer(BaseAnalyzer):
    """Run behavioural alignment analysis on JS/TS MCP server source.

    Drop-in counterpart of
    :class:`mcpscanner.core.analyzers.behavioral.code_analyzer.
    BehavioralCodeAnalyzer`; same constructor, same ``analyze`` signature,
    same ``SecurityFinding`` output shape. Operators can wire either one
    into the same scanner pipeline.
    """

    def __init__(self, config: Config):
        super().__init__(name="Behavioural (JS)")
        self._config = config
        self.alignment_orchestrator = AlignmentOrchestrator(config)
        self.logger.debug(
            "JSBehavioralCodeAnalyzer initialised with alignment orchestrator"
        )

    async def analyze(
        self, content: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze a JS/TS file, directory, or source string for
        docstring/behaviour mismatches.

        Args:
            content: File path, directory path, or raw JS/TS source string.
            context: Free-form context dict; ``file_path`` is used when
                ``content`` is raw source.

        Returns:
            ``SecurityFinding`` records for each mismatch the orchestrator
            confirms.
        """
        try:
            if os.path.isdir(content):
                return await self._analyze_directory(content, context)
            if os.path.isfile(content):
                return await self._analyze_file(content, context)
            # Treat as raw source.
            return await self._analyze_source_code(
                content, context.get("file_path", "inline.ts"), context
            )
        except Exception as e:  # noqa: BLE001 - surface any failure as zero findings
            self.logger.error(
                "js behavioural analysis failed error=%s", e, exc_info=True
            )
            return []

    # ------------------------------------------------------------------
    # File / directory walking
    # ------------------------------------------------------------------

    async def _analyze_directory(
        self, directory: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Recurse into ``directory``, analyse every JS/TS file we find."""
        files = self._find_js_files(directory)
        self.logger.debug(
            "js behavioural scan root=%s files=%d", directory, len(files)
        )
        findings: List[SecurityFinding] = []
        for path in files:
            file_findings = await self._analyze_file(path, context)
            findings.extend(file_findings)
        return findings

    async def _analyze_file(
        self, file_path: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Read ``file_path`` and run the source through the extractor +
        orchestrator pipeline. Per-file errors are logged and swallowed so
        a single bad file can't tank the whole scan."""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MCPScannerConstants.MAX_FILE_SIZE_BYTES * 5:
                self.logger.error(
                    "js behavioural skip file=%s size=%d -- too large",
                    file_path,
                    file_size,
                )
                return []
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                source_code = fh.read()
        except OSError as e:
            self.logger.warning(
                "js behavioural failed_to_read file=%s error=%s", file_path, e
            )
            return []

        findings = await self._analyze_source_code(source_code, file_path, context)
        for finding in findings:
            if finding.details is not None:
                finding.details["source_file"] = file_path
        return findings

    def _find_js_files(self, directory: str) -> List[str]:
        """Return absolute paths of every JS/TS file under ``directory``,
        skipping vendored deps and build artefacts."""
        out: List[str] = []
        root = Path(directory)
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _JS_EXTENSIONS:
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            # Skip hidden dotfiles.
            if any(part.startswith(".") for part in path.parts):
                continue
            out.append(str(path))
        return sorted(out)

    # ------------------------------------------------------------------
    # Per-source orchestrator call
    # ------------------------------------------------------------------

    async def _analyze_source_code(
        self, source_code: str, file_path: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Extract function contexts from ``source_code`` and run them
        through the alignment orchestrator."""
        from ...static_analysis.javascript import JSContextExtractor

        try:
            extractor = JSContextExtractor(source_code, file_path)
        except ValueError as e:
            # Unsupported extension; raw source analysed via analyze() with
            # no .ts suffix is the usual cause.
            self.logger.debug(
                "js behavioural unsupported_extension file=%s error=%s", file_path, e
            )
            return []

        try:
            contexts = extractor.extract_mcp_function_contexts()
        except Exception as e:  # noqa: BLE001
            self.logger.error(
                "js behavioural extract_failed file=%s error=%s", file_path, e
            )
            return []

        if not contexts:
            self.logger.debug("js behavioural no_mcp_calls file=%s", file_path)
            return []

        self.logger.debug(
            "js behavioural functions file=%s count=%d", file_path, len(contexts)
        )

        findings: List[SecurityFinding] = []
        for ctx in contexts:
            result = await self.alignment_orchestrator.check_alignment(ctx)
            if result is None:
                continue
            analysis, returned_ctx = result
            finding = self._create_security_finding(analysis, returned_ctx, file_path)
            if finding is not None:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------
    # Finding construction (parity with Python BehavioralCodeAnalyzer)
    # ------------------------------------------------------------------

    def _create_security_finding(
        self, analysis: Dict[str, Any], func_context, file_path: str
    ) -> Optional[SecurityFinding]:
        """Translate one ``(analysis, ctx)`` orchestrator result into a
        ``SecurityFinding``. Mirrors the Python analyzer so the downstream
        reporters don't need a JS-specific code path."""
        try:
            threat_name = (analysis.get("threat_name") or "").upper()
            if not threat_name:
                self.logger.warning(
                    "js behavioural no_threat_name function=%s", func_context.name
                )
                return None
            try:
                threat_info = ThreatMapping.get_threat_mapping("behavioral", threat_name)
            except ValueError as e:
                self.logger.warning(
                    "js behavioural unknown_threat threat=%s function=%s error=%s",
                    threat_name,
                    func_context.name,
                    e,
                )
                return None

            severity = threat_info["severity"]
            description_claims = analysis.get("description_claims", "")
            actual_behavior = analysis.get("actual_behavior", "")
            line_info = f"Line {func_context.line_number}: "

            if description_claims and actual_behavior:
                summary = (
                    f"{line_info}{threat_name} - "
                    f"Description claims: '{description_claims}' | "
                    f"Actual behavior: {actual_behavior}"
                )
            else:
                summary = f"{line_info}{threat_name} in {func_context.name}"

            return SecurityFinding(
                severity=severity,
                summary=summary,
                analyzer="Behavioral",
                threat_category=threat_info["scanner_category"],
                details={
                    "function_name": func_context.name,
                    "decorator_type": (
                        func_context.decorator_types[0]
                        if func_context.decorator_types
                        else "unknown"
                    ),
                    "line_number": func_context.line_number,
                    "source_file": file_path,
                    "threat_name": threat_name,
                    "threat_type": threat_name,
                    "mismatch_type": analysis.get("mismatch_type"),
                    "description_claims": description_claims,
                    "actual_behavior": actual_behavior,
                    "security_implications": analysis.get("security_implications"),
                    "confidence": analysis.get("confidence"),
                    "dataflow_evidence": analysis.get("dataflow_evidence"),
                    "threat_vulnerability_classification": analysis.get(
                        "threat_vulnerability_classification"
                    ),
                    "aitech": threat_info["aitech"],
                    "aitech_name": threat_info["aitech_name"],
                    "aisubtech": threat_info["aisubtech"],
                    "aisubtech_name": threat_info["aisubtech_name"],
                    "taxonomy_description": threat_info["description"],
                    "language": "javascript",
                },
            )
        except Exception as e:  # noqa: BLE001
            self.logger.error(
                "js behavioural finding_creation_failed error=%s", e, exc_info=True
            )
            return None
