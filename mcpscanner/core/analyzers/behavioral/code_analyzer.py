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

"""Behavioral Code Analyzer for MCP Scanner.

This analyzer detects mismatches between MCP tool docstrings and their actual
code behavior using deep code analysis and LLM-based comparison.

This analyzer:
1. Identifies MCP decorator usage (@mcp.tool, @mcp.prompt, @mcp.resource)
2. Extracts comprehensive code context (dataflow, taint, constants)
3. Analyzes actual code behavior using full AST + dataflow analysis
4. Uses LLM to detect semantic mismatches between description and implementation
"""

import asyncio
import os
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ....config.config import Config
from ....config.constants import MCPScannerConstants
from ....threats.threats import ThreatMapping
from ....utils.log_format import sanitize_log_value, truncate
from ....utils.path_safety import filter_safe_paths, safe_resolve_root
from ...static_analysis.context_extractor import ContextExtractor
from ...static_analysis.native_analyzer import NativeAnalyzer
from ...static_analysis.interprocedural.call_graph_analyzer import CallGraphAnalyzer
from ...static_analysis.interprocedural.treesitter_call_graph import (
    TreeSitterCallGraphAnalyzer,
)
from ..base import BaseAnalyzer, SecurityFinding
from .alignment import AlignmentOrchestrator


_SEVERITY_DISPLAY_ORDER = (
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "SAFE",
    "ERROR",
    "UNKNOWN",
)


@dataclass(slots=True)
class _AcceptedFile:
    """A capability-file that survived the byte-level prefilter."""

    path: str
    source_bytes: bytes
    source_text: str


class BehavioralCodeAnalyzer(BaseAnalyzer):
    """Analyzer that detects docstring/behavior mismatches in MCP tool source code.

    This analyzer:
    1. Extracts MCP tool source code from the server
    2. Performs deep dataflow analysis using the behavioural engine
    3. Uses LLM to compare docstring claims vs actual behavior
    4. Detects hidden behaviors like data exfiltration

    Example:
        >>> from mcpscanner import Config
        >>> from mcpscanner.core.analyzers import BehaviouralAnalyzer
        >>> analyzer = BehaviouralAnalyzer(config)
        >>> findings = await analyzer.analyze("/path/to/mcp_server.py", {})
    """

    def __init__(self, config: Config):
        """Initialize the BehavioralCodeAnalyzer.

        Args:
            config: Configuration containing LLM credentials

        Raises:
            ValueError: If LLM provider API key is not configured
        """
        super().__init__(name="Behavioural")
        self._config = config

        # Initialize alignment orchestrator (handles all LLM interaction)
        self.alignment_orchestrator = AlignmentOrchestrator(config)

        # Tracks every MCP tool/function that was analyzed during the most recent
        # analyze() call, regardless of whether a finding was produced. This lets
        # callers report on ALL tools detected during a scan (safe and unsafe),
        # not only the ones that triggered a SecurityFinding.
        self.analyzed_functions: List[Dict[str, Any]] = []

        self.logger.debug(
            "BehavioralCodeAnalyzer initialized with alignment verification"
        )

    @staticmethod
    def _describe_scan_target(content: str) -> tuple[str, str]:
        """Classify ``content`` as a directory/file/inline scan target."""
        if os.path.isdir(content):
            return "directory", sanitize_log_value(content)
        if os.path.isfile(content):
            return "file", sanitize_log_value(content)
        return "inline", f"<source:{len(content)}b>"

    def _log_scan_start(
        self,
        *,
        scan_mode: str,
        scan_target: str,
        tool_label: str,
    ) -> None:
        """Emit the start-of-scan INFO line."""
        self.logger.info(
            "behavioral scan start mode=%s target=%s tool=%s",
            scan_mode,
            scan_target,
            tool_label,
        )

    def _format_severity_fields(
        self, findings: List[SecurityFinding]
    ) -> tuple[str, int]:
        """Build the ``sev_<NAME>=N`` rollup and return ``(fields, non_safe)``."""
        severity_counts: Counter[str] = Counter(
            (getattr(f, "severity", "") or "UNKNOWN") for f in findings
        )
        non_safe_total = sum(v for k, v in severity_counts.items() if k != "SAFE")
        ordered_keys = [s for s in _SEVERITY_DISPLAY_ORDER if s in severity_counts]
        ordered_keys += [
            s for s in severity_counts if s not in _SEVERITY_DISPLAY_ORDER
        ]
        sev_fields = " ".join(
            f"sev_{key}={severity_counts[key]}" for key in ordered_keys
        )
        return sev_fields, non_safe_total

    def _log_scan_summary(
        self,
        *,
        scan_mode: str,
        scan_target: str,
        tool_label: str,
        findings: List[SecurityFinding],
        scan_ms: int,
    ) -> None:
        """Emit the end-of-scan rollup + delegate the alignment summary."""
        sev_fields, non_safe_total = self._format_severity_fields(findings)
        self.logger.info(
            "behavioral scan done mode=%s target=%s findings=%d non_safe=%d "
            "analyzed_functions=%d duration_ms=%d %s",
            scan_mode,
            scan_target,
            len(findings),
            non_safe_total,
            len(self.analyzed_functions),
            scan_ms,
            sev_fields,
        )
        try:
            self.alignment_orchestrator.log_summary(
                scope=f"{scan_mode}:{tool_label}",
            )
        except Exception:  # pragma: no cover - logging must never raise
            pass

    async def analyze(
        self, content: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze MCP tool source code for docstring/behavior mismatches.

        Returns one ``SecurityFinding`` per scanned MCP tool/function.
        Tools with no detected mismatch are returned with
        ``severity == "SAFE"`` and ``threat_category == ""``.

        Args:
            content: File path to a source file/directory OR raw source
                code string.
            context: Analysis context with ``tool_name``, ``file_path``,
                etc.

        Returns:
            List of ``SecurityFinding`` objects covering every scanned
            tool. Empty when no functions were extractable at all.
        """
        scan_mode: str = "unknown"
        scan_target: str = "-"
        tool_label: str = "-"
        scan_start = time.perf_counter()
        # Reset cross-call state *before* anything that can raise, so a
        # failure between calls doesn't leave stale ``analyzed_functions``
        # behind for the next caller.
        self.analyzed_functions = []
        try:
            all_findings = []
            self.alignment_orchestrator.reset_stats()

            # ``_describe_scan_target`` issues two ``os.path.is*`` syscalls;
            # those can block for seconds on network mounts. Offload them
            # so the event loop stays responsive.
            scan_mode, scan_target = await asyncio.to_thread(
                self._describe_scan_target, content
            )
            tool_label = sanitize_log_value(
                context.get("tool_name") or context.get("file_path") or "<inline>"
            )
            self._log_scan_start(
                scan_mode=scan_mode,
                scan_target=scan_target,
                tool_label=tool_label,
            )

            # Check if content is a directory
            if os.path.isdir(content):
                self.logger.debug(f"Scanning directory: {content}")

                source_files = self._find_source_files(content)
                self.logger.debug(
                    f"Found {len(source_files)} source file(s) to analyze"
                )

                capability_files = self._prefilter_capability_files(source_files)
                self.logger.info(
                    "behavioral prefilter scanned=%d kept=%d",
                    len(source_files),
                    len(capability_files),
                )

                if source_files and not capability_files:
                    self.logger.warning(
                        "behavioral no_mcp_capabilities scanned=%d dir=%s "
                        "reason=no_mcp_capability_markers",
                        len(source_files),
                        sanitize_log_value(content),
                    )

                # Partition files by language family
                python_files: List[_AcceptedFile] = []
                ts_files_by_lang: Dict[str, List[_AcceptedFile]] = {}
                for accepted in capability_files:
                    ext = Path(accepted.path).suffix.lower()
                    if ext in self._PYTHON_EXTENSIONS:
                        python_files.append(accepted)
                    elif ext in self._EXT_TO_TS_LANGUAGE:
                        lang = self._EXT_TO_TS_LANGUAGE[ext]
                        ts_files_by_lang.setdefault(lang, []).append(accepted)

                if capability_files:
                    lang_counts = {
                        "python": len(python_files),
                        **{lang: len(files) for lang, files in sorted(ts_files_by_lang.items())},
                    }
                    lang_fields = " ".join(
                        f"lang_{lang}={n}" for lang, n in lang_counts.items() if n
                    )
                    self.logger.info(
                        "behavioral languages %s", lang_fields
                    )

                # Build Python call graph
                py_call_graph_analyzer: Optional[CallGraphAnalyzer] = None
                if python_files:
                    py_call_graph_analyzer = CallGraphAnalyzer()

                # Build per-language tree-sitter call graph analyzers
                ts_call_graph_analyzers: Dict[str, TreeSitterCallGraphAnalyzer] = {}
                for lang in ts_files_by_lang:
                    ts_call_graph_analyzers[lang] = TreeSitterCallGraphAnalyzer(lang)

                total_size = 0
                for accepted in capability_files:
                    try:
                        if accepted.source_bytes:
                            file_size = len(accepted.source_bytes)
                        else:
                            file_size = os.path.getsize(accepted.path)
                        total_size += file_size

                        if file_size > MCPScannerConstants.MAX_FILE_SIZE_BYTES * 5:
                            self.logger.error(
                                f"Very large file detected, skipping: {accepted.path} ({file_size:,} bytes)"
                            )
                            continue
                        elif file_size > MCPScannerConstants.MAX_FILE_SIZE_BYTES:
                            self.logger.debug(
                                f"Large file detected: {accepted.path} ({file_size:,} bytes)"
                            )

                        if accepted.source_text:
                            source_code = accepted.source_text
                        else:
                            with open(accepted.path, "r", encoding="utf-8") as f:
                                source_code = f.read()

                        ext = Path(accepted.path).suffix.lower()
                        if ext in self._PYTHON_EXTENSIONS and py_call_graph_analyzer:
                            py_call_graph_analyzer.add_file(
                                Path(accepted.path), source_code
                            )
                        elif ext in self._EXT_TO_TS_LANGUAGE:
                            lang = self._EXT_TO_TS_LANGUAGE[ext]
                            ts_call_graph_analyzers[lang].add_file(
                                Path(accepted.path), source_code
                            )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to add file {accepted.path} to cross-file analyzer: {e}"
                        )

                self.logger.debug(
                    f"Total directory size: {total_size:,} bytes across {len(capability_files)} files"
                )
                if total_size > 10_000_000:  # 10MB
                    self.logger.warning(
                        f"Detected large codebase ({total_size:,} bytes). Analysis performance may be affected."
                    )

                # Build call graphs
                if py_call_graph_analyzer:
                    call_graph = py_call_graph_analyzer.build_call_graph()
                    self.logger.debug(
                        f"Built Python call graph with {len(call_graph.functions)} functions"
                    )

                for lang, ts_analyzer in ts_call_graph_analyzers.items():
                    ts_cg = ts_analyzer.build_call_graph()
                    self.logger.debug(
                        f"Built {lang} call graph with {len(ts_cg.functions)} functions"
                    )

                # Analyze each file with its language-appropriate call graph
                for accepted in capability_files:
                    self.logger.debug(f"Analyzing file: {accepted.path}")
                    ext = Path(accepted.path).suffix.lower()
                    if ext in self._PYTHON_EXTENSIONS:
                        file_cga = py_call_graph_analyzer
                    elif ext in self._EXT_TO_TS_LANGUAGE:
                        lang = self._EXT_TO_TS_LANGUAGE[ext]
                        file_cga = ts_call_graph_analyzers.get(lang)
                    else:
                        file_cga = None

                    file_start = time.perf_counter()
                    file_findings = await self._analyze_file(
                        accepted.path,
                        context,
                        file_cga,
                        cached_source=accepted.source_text or None,
                    )
                    file_ms = int((time.perf_counter() - file_start) * 1000)
                    non_safe = sum(
                        1 for f in file_findings if getattr(f, "severity", "") != "SAFE"
                    )
                    self.logger.info(
                        "behavioral file done path=%s findings=%d non_safe=%d duration_ms=%d",
                        sanitize_log_value(accepted.path),
                        len(file_findings),
                        non_safe,
                        file_ms,
                    )
                    all_findings.extend(file_findings)

            # Check if content is a single file
            elif os.path.isfile(content):
                ext = Path(content).suffix.lower()
                cross_file_analyzer = None
                try:
                    with open(content, "r", encoding="utf-8") as f:
                        source_code = f.read()

                    if ext in self._PYTHON_EXTENSIONS:
                        cga = CallGraphAnalyzer()
                        cga.add_file(Path(content), source_code)
                        call_graph = cga.build_call_graph()
                        cross_file_analyzer = cga
                    elif ext in self._EXT_TO_TS_LANGUAGE:
                        lang = self._EXT_TO_TS_LANGUAGE[ext]
                        ts_cga = TreeSitterCallGraphAnalyzer(lang)
                        ts_cga.add_file(Path(content), source_code)
                        ts_cga.build_call_graph()
                        cross_file_analyzer = ts_cga
                    else:
                        cga = CallGraphAnalyzer()
                        cga.add_file(Path(content), source_code)
                        call_graph = cga.build_call_graph()
                        cross_file_analyzer = cga

                    if cross_file_analyzer:
                        self.logger.debug(
                            f"Built call graph for {content}"
                        )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to build call graph for {content}: {e}"
                    )
                    cross_file_analyzer = None

                all_findings = await self._analyze_file(
                    content, context, cross_file_analyzer
                )

            else:
                # Content is source code string
                cross_file_analyzer = None
                try:
                    temp_path = Path(context.get("file_path", "inline_code.py"))
                    ext = temp_path.suffix.lower()

                    if ext in self._PYTHON_EXTENSIONS or ext not in self._EXT_TO_TS_LANGUAGE:
                        cross_file_analyzer = CallGraphAnalyzer()
                        cross_file_analyzer.add_file(temp_path, content)
                        call_graph = cross_file_analyzer.build_call_graph()
                    else:
                        lang = self._EXT_TO_TS_LANGUAGE[ext]
                        ts_cga = TreeSitterCallGraphAnalyzer(lang)
                        ts_cga.add_file(temp_path, content)
                        ts_cga.build_call_graph()
                        cross_file_analyzer = ts_cga

                    self.logger.debug(
                        "Built call graph for inline source"
                    )
                    context["cross_file_analyzer"] = cross_file_analyzer
                except Exception as e:
                    self.logger.debug(
                        f"Could not build call graph for inline source: {e}"
                    )

                all_findings = await self._analyze_source_code(content, context)

            self._log_scan_summary(
                scan_mode=scan_mode,
                scan_target=scan_target,
                tool_label=tool_label,
                findings=all_findings,
                scan_ms=int((time.perf_counter() - scan_start) * 1000),
            )
            return all_findings

        except Exception as e:
            self.logger.error(
                "behavioral scan failed mode=%s target=%s error_type=%s error=%s",
                scan_mode,
                scan_target,
                type(e).__name__,
                truncate(e),
                exc_info=True,
            )
            return []

    _EXT_TO_TS_LANGUAGE = {
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
        ".go": "go",
        ".java": "java",
        ".kt": "kotlin", ".kts": "kotlin",
        ".cs": "c_sharp",
        ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
        ".rs": "rust",
        ".php": "php", ".phtml": "php",
    }

    _PYTHON_EXTENSIONS = {".py", ".pyw"}

    def _find_source_files(self, directory: str) -> List[str]:
        """Find all supported source files in a directory.

        Supports Python, TypeScript, JavaScript, Go, Java, Kotlin, C#, Ruby,
        Rust, and PHP files.

        Args:
            directory: Directory path to search

        Returns:
            List of source file paths
        """
        source_files = []
        path = Path(directory)
        resolved_root = safe_resolve_root(directory)

        extensions = self._PYTHON_EXTENSIONS | set(self._EXT_TO_TS_LANGUAGE.keys())

        candidates: List[Path] = []
        for ext in extensions:
            for source_file in path.rglob(f"*{ext}"):
                file_str = str(source_file)
                if (
                    "__pycache__" not in file_str
                    and "node_modules" not in file_str
                    and not any(part.startswith(".") for part in source_file.parts)
                ):
                    candidates.append(source_file)

        safe_candidates, _skipped = filter_safe_paths(
            candidates, resolved_root, audit_label="behavioral"
        )
        for source_file in safe_candidates:
            source_files.append(str(source_file))

        return sorted(source_files)

    def _prefilter_capability_files(
        self, source_files: List[str]
    ) -> List[_AcceptedFile]:
        """Return the subset of ``source_files`` that contain MCP markers."""
        from mcpscanner.core.static_analysis import NativeAnalyzer

        accepted: List[_AcceptedFile] = []
        for src_file in source_files:
            try:
                file_size = os.path.getsize(src_file)
                if file_size > MCPScannerConstants.MAX_FILE_SIZE_BYTES * 5:
                    self.logger.debug(
                        f"Prefilter skipping huge file: {src_file} "
                        f"({file_size:,} bytes)"
                    )
                    continue
                with open(src_file, "rb") as f:
                    source_bytes = f.read()
            except OSError as e:
                self.logger.debug(f"Prefilter could not read {src_file}: {e}")
                accepted.append(
                    _AcceptedFile(path=src_file, source_bytes=b"", source_text="")
                )
                continue
            try:
                source_code = source_bytes.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                continue
            analyzer = NativeAnalyzer(source_code, src_file)
            if analyzer._has_mcp_markers():
                accepted.append(
                    _AcceptedFile(
                        path=src_file,
                        source_bytes=source_bytes,
                        source_text=source_code,
                    )
                )
        return accepted

    def _find_python_files(self, directory: str) -> List[str]:
        """Find all Python files in a directory (legacy method).

        Args:
            directory: Directory path to search

        Returns:
            List of Python file paths
        """
        python_files: List[str] = []
        path = Path(directory)
        resolved_root = safe_resolve_root(directory)

        candidates: List[Path] = []
        for py_file in path.rglob("*.py"):
            if "__pycache__" not in str(py_file) and not any(
                part.startswith(".") for part in py_file.parts
            ):
                candidates.append(py_file)

        safe_candidates, _skipped = filter_safe_paths(
            candidates, resolved_root, audit_label="behavioral"
        )
        for py_file in safe_candidates:
            python_files.append(str(py_file))

        return sorted(python_files)

    async def _analyze_file(
        self,
        file_path: str,
        context: Dict[str, Any],
        cross_file_analyzer: Optional[
            Union[CallGraphAnalyzer, TreeSitterCallGraphAnalyzer]
        ] = None,
        *,
        cached_source: Optional[str] = None,
    ) -> List[SecurityFinding]:
        """Analyze a single source file.

        Args:
            file_path: Path to source file
            context: Analysis context
            cross_file_analyzer: Optional cross-file analyzer (Python or tree-sitter)
            cached_source: Pre-read source text when the caller already
                holds the file contents.

        Returns:
            List of SecurityFinding objects
        """
        analyze_start = time.perf_counter()
        try:
            if cached_source is not None:
                source_code = cached_source
            else:
                with open(file_path, "r", encoding="utf-8") as f:
                    source_code = f.read()

            file_context = context.copy()
            file_context["file_path"] = file_path
            file_context["cross_file_analyzer"] = cross_file_analyzer

            findings = await self._analyze_source_code(source_code, file_context)

            # Tag findings with file path
            for finding in findings:
                if finding.details:
                    finding.details["source_file"] = file_path

            self.logger.debug(
                "behavioral _analyze_file ok path=%s findings=%d source_length=%d "
                "duration_ms=%d",
                sanitize_log_value(file_path),
                len(findings),
                len(source_code),
                int((time.perf_counter() - analyze_start) * 1000),
            )
            return findings

        except Exception as e:
            self.logger.error(
                "behavioral _analyze_file failed path=%s duration_ms=%d "
                "error_type=%s error=%s",
                sanitize_log_value(file_path),
                int((time.perf_counter() - analyze_start) * 1000),
                type(e).__name__,
                truncate(e),
            )
            return []

    async def _analyze_source_code(
        self, source_code: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze source code for docstring/behavior mismatches.

        Args:
            source_code: Source code to analyze
            context: Analysis context with file_path

        Returns:
            List of security findings.
        """
        file_path = context.get("file_path", "unknown")
        findings = []
        func_contexts = []

        # Determine file type
        file_ext = Path(file_path).suffix.lower()
        is_python = file_ext in {".py", ".pyw"}
        is_js_ts = file_ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}

        try:
            if is_python:
                # Try primary ContextExtractor first (for MCP-decorated functions)
                try:
                    extractor = ContextExtractor(source_code, file_path)
                    func_contexts = extractor.extract_mcp_function_contexts()
                    if func_contexts:
                        self.logger.debug(
                            f"Found {len(func_contexts)} MCP functions in {file_path}"
                        )
                except Exception as e:
                    self.logger.debug(
                        f"ContextExtractor failed for {file_path}: {e}, using NativeAnalyzer"
                    )
                    func_contexts = []

                if not func_contexts:
                    self.logger.debug(
                        f"No MCP functions found in {file_path}, using NativeAnalyzer fallback"
                    )
                    native_analyzer = NativeAnalyzer(source_code, file_path)
                    func_contexts = native_analyzer.extract_mcp_capability_contexts(
                        cross_file_analyzer=context.get("cross_file_analyzer")
                    )
                    if func_contexts:
                        self.logger.debug(
                            f"NativeAnalyzer extracted {len(func_contexts)} MCP capabilities from {file_path}"
                        )

            elif is_js_ts:
                self.logger.debug(f"Using NativeAnalyzer for JS/TS file: {file_path}")
                native_analyzer = NativeAnalyzer(source_code, file_path)
                func_contexts = native_analyzer.extract_mcp_capability_contexts(
                    cross_file_analyzer=context.get("cross_file_analyzer")
                )
                if func_contexts:
                    self.logger.debug(
                        f"NativeAnalyzer extracted {len(func_contexts)} MCP capabilities from {file_path}"
                    )

            else:
                self.logger.debug(f"Unknown file type {file_path}, trying NativeAnalyzer")
                native_analyzer = NativeAnalyzer(source_code, file_path)
                func_contexts = native_analyzer.extract_mcp_capability_contexts(
                    cross_file_analyzer=context.get("cross_file_analyzer")
                )
                if func_contexts:
                    self.logger.debug(
                        f"NativeAnalyzer detected {native_analyzer.language}, "
                        f"extracted {len(func_contexts)} MCP capabilities"
                    )

            if not func_contexts:
                self.logger.debug(f"No functions found in {file_path}")
                return findings

            # Record every function we are about to analyze so that callers
            # can enumerate all tools detected during the scan (including
            # functions that later come back clean with no findings).
            for fc in func_contexts:
                self.analyzed_functions.append(
                    {
                        "name": getattr(fc, "name", "unknown"),
                        "decorator_types": list(getattr(fc, "decorator_types", []) or []),
                        "line_number": getattr(fc, "line_number", 0),
                        "source_file": file_path,
                        "docstring": getattr(fc, "docstring", None) or "",
                    }
                )

            self.logger.debug(f"Analyzing {len(func_contexts)} functions in {file_path}")

            # Enrich with cross-file context if available
            if context.get("cross_file_analyzer"):
                for func_context in func_contexts:
                    self._enrich_with_cross_file_context(
                        func_context, file_path, context["cross_file_analyzer"]
                    )

            # Batch alignment checks to reduce LLM round-trips; the
            # default batch size mirrors ``context['batch_size']``.
            use_batching = context.get("use_batching", True)
            batch_size = context.get("batch_size", 5)

            if use_batching and len(func_contexts) > 1:
                self.logger.debug(f"Using batched analysis with batch_size={batch_size}")
                batch_results = await self.alignment_orchestrator.check_alignment_batch(
                    func_contexts, batch_size=batch_size
                )
                for analysis, ctx in batch_results:
                    finding = self._create_security_finding(analysis, ctx, file_path)
                    if finding:
                        findings.append(finding)
            else:
                # Fallback to individual analysis
                for func_context in func_contexts:
                    # Check function source size (configurable via constants)
                    func_source_size = (
                        len(func_context.source) if hasattr(func_context, "source") else 0
                    )
                    func_line_count = (
                        func_context.line_count
                        if hasattr(func_context, "line_count")
                        else 0
                    )

                    if func_source_size > MCPScannerConstants.MAX_FUNCTION_SIZE_BYTES:
                        self.logger.warning(
                            f"Large function detected: {func_context.name} "
                            f"({func_source_size:,} bytes, {func_line_count} lines) - prompt may be oversized"
                        )
                    elif func_line_count > 500:
                        self.logger.debug(
                            f"Long function: {func_context.name} ({func_line_count} lines)"
                        )

                    result = await self.alignment_orchestrator.check_alignment(func_context)

                    if result:
                        analysis, ctx = result
                        finding = self._create_security_finding(analysis, ctx, file_path)
                        if finding:
                            findings.append(finding)

            funcs_with_findings = {
                (f.details or {}).get("function_name")
                for f in findings
                if (f.details or {}).get("source_file") == file_path
            }
            funcs_with_findings.discard(None)
            errored_funcs = set(
                getattr(
                    self.alignment_orchestrator, "errored_function_names", set()
                )
            )
            for fc in func_contexts:
                name = getattr(fc, "name", None)
                if not name or name in funcs_with_findings:
                    continue
                decorator_types = getattr(fc, "decorator_types", None) or []
                # An errored function is "unknown", not "safe". Synthesise
                # an UNKNOWN-severity record (the only non-SAFE level the
                # SecurityFinding framework accepts here) so the reporter
                # doesn't claim we successfully analysed something we
                # never did.
                if name in errored_funcs:
                    findings.append(
                        SecurityFinding(
                            severity="UNKNOWN",
                            summary="Alignment check did not complete; finding is inconclusive",
                            threat_category="",
                            analyzer="Behavioral",
                            details={
                                "function_name": name,
                                "decorator_type": (
                                    decorator_types[0] if decorator_types else "unknown"
                                ),
                                "line_number": getattr(fc, "line_number", 0),
                                "source_file": file_path,
                                "no_findings": False,
                                "analysis_status": "errored",
                            },
                        )
                    )
                    continue
                findings.append(
                    SecurityFinding(
                        severity="SAFE",
                        summary="No behavioral mismatches detected",
                        threat_category="",
                        analyzer="Behavioral",
                        details={
                            "function_name": name,
                            "decorator_type": (
                                decorator_types[0] if decorator_types else "unknown"
                            ),
                            "line_number": getattr(fc, "line_number", 0),
                            "source_file": file_path,
                            "no_findings": True,
                        },
                    )
                )

        except Exception as e:
            self.logger.error(
                "behavioral _analyze_source_code failed path=%s error_type=%s error=%s",
                sanitize_log_value(file_path),
                type(e).__name__,
                truncate(e),
                exc_info=True,
            )

        return findings

    def _create_security_finding(
        self, analysis: Dict[str, Any], func_context, file_path: str
    ) -> Optional[SecurityFinding]:
        """Create SecurityFinding from alignment analysis using threat mappings.

        Args:
            analysis: Analysis dict from LLM with threat_name, severity, etc.
            func_context: FunctionContext with code details
            file_path: Path to the source file

        Returns:
            SecurityFinding with threat taxonomy mappings or None if invalid
        """
        try:
            threat_name = analysis.get("threat_name", "").upper()

            if not threat_name:
                self.logger.warning(
                    f"No threat_name in analysis for {func_context.name}"
                )
                return None

            # Get threat mapping from taxonomy (severity is derived here, not from LLM)
            try:
                threat_info = ThreatMapping.get_threat_mapping(
                    "behavioral", threat_name
                )
            except ValueError as e:
                self.logger.warning(f"Unknown threat name '{threat_name}': {e}")
                return None

            severity = threat_info["severity"]

            # For non-Python files, skip INFO severity and GENERAL DESCRIPTION-CODE MISMATCH
            is_python = file_path.endswith(".py")
            if not is_python:
                if severity == "INFO":
                    self.logger.debug(
                        f"Skipping INFO finding for non-Python file: {file_path}"
                    )
                    return None
                if threat_name == "GENERAL DESCRIPTION-CODE MISMATCH":
                    self.logger.debug(
                        f"Skipping GENERAL DESCRIPTION-CODE MISMATCH for non-Python file: {file_path}"
                    )
                    return None

            # Build threat summary from analysis
            description_claims = analysis.get("description_claims", "")
            actual_behavior = analysis.get("actual_behavior", "")
            line_info = f"Line {func_context.line_number}: "

            if description_claims and actual_behavior:
                threat_summary = f"{line_info}{threat_name} - Description claims: '{description_claims}' | Actual behavior: {actual_behavior}"
            else:
                threat_summary = f"{line_info}{threat_name} in {func_context.name}"

            # Create SecurityFinding with complete threat taxonomy
            # SecurityFinding will auto-generate mcp_taxonomy from threat_type
            # Also include taxonomy in details for display purposes
            finding = SecurityFinding(
                severity=severity,
                summary=threat_summary,
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
                    "threat_type": threat_name,  # Used by SecurityFinding for auto-generating mcp_taxonomy
                    "mismatch_type": analysis.get("mismatch_type"),
                    "description_claims": description_claims,
                    "actual_behavior": actual_behavior,
                    "security_implications": analysis.get("security_implications"),
                    "confidence": analysis.get("confidence"),
                    "dataflow_evidence": analysis.get("dataflow_evidence"),
                    # Include threat/vulnerability classification from second alignment layer
                    "threat_vulnerability_classification": analysis.get(
                        "threat_vulnerability_classification"
                    ),
                    # Include MCP Taxonomy in details for easy access in reports
                    "aitech": threat_info["aitech"],
                    "aitech_name": threat_info["aitech_name"],
                    "aisubtech": threat_info["aisubtech"],
                    "aisubtech_name": threat_info["aisubtech_name"],
                    "taxonomy_description": threat_info["description"],
                },
            )

            return finding

        except Exception as e:
            self.logger.error(f"Failed to create security finding: {e}", exc_info=True)
            return None

    def _enrich_with_cross_file_context(
        self,
        func_context,
        file_path: str,
        call_graph_analyzer: Union[CallGraphAnalyzer, TreeSitterCallGraphAnalyzer],
    ) -> None:
        """Enrich function context with cross-file analysis data.

        Args:
            func_context: FunctionContext to enrich
            file_path: Source file path
            call_graph_analyzer: CallGraphAnalyzer or TreeSitterCallGraphAnalyzer
        """
        try:
            full_func_name = f"{file_path}::{func_context.name}"

            reachable = call_graph_analyzer.get_reachable_functions(full_func_name)
            if reachable:
                func_context.reachable_functions = reachable

            if func_context.parameters:
                param_names = [
                    p.get("name") for p in func_context.parameters if p.get("name")
                ]
                if param_names:
                    if isinstance(call_graph_analyzer, TreeSitterCallGraphAnalyzer):
                        flow_info = call_graph_analyzer.analyze_cross_file_flows(
                            full_func_name, param_names
                        )
                    else:
                        flow_info = (
                            call_graph_analyzer.analyze_parameter_flow_across_files(
                                full_func_name, param_names
                            )
                        )

                    if flow_info.get("cross_file_flows"):
                        func_context.cross_file_calls = flow_info["cross_file_flows"]

                    func_context.dataflow_summary["cross_file_analysis"] = {
                        "total_reachable": len(reachable),
                        "files_involved": flow_info.get("total_files_involved", 0),
                        "param_influenced_functions": len(
                            flow_info.get("param_influenced_functions", [])
                        ),
                    }

        except Exception as e:
            self.logger.warning(f"Failed to enrich with cross-file context: {e}")
