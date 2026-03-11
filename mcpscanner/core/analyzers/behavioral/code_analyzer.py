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

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ....config.config import Config
from ....config.constants import MCPScannerConstants
from ....threats.threats import ThreatMapping
from ...static_analysis.context_extractor import ContextExtractor
from ...static_analysis.interprocedural.call_graph_analyzer import CallGraphAnalyzer
from ..base import BaseAnalyzer, SecurityFinding
from ..deterministic_classifier import DeterministicClassifier, RuleMatch
from ...policy.network_policy import NetworkPolicy
from ...policy.filesystem_policy import FilesystemPolicy
from ...policy.data_classifier import DataClassifier
from .alignment import AlignmentOrchestrator


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

        # Deterministic engine (always runs)
        self._deterministic = DeterministicClassifier()

        # Policy modules (only active when configured)
        self._network_policy = NetworkPolicy(
            config_path=getattr(config, "network_policy_path", None)
        )
        self._filesystem_policy = FilesystemPolicy(
            config_path=getattr(config, "filesystem_policy_path", None)
        )
        self._data_classifier = DataClassifier()

        # LLM fallback flag
        self._use_llm_fallback = getattr(config, "use_llm_fallback", True)

        self.logger.debug(
            "BehavioralCodeAnalyzer initialized with deterministic engine "
            f"(llm_fallback={'on' if self._use_llm_fallback else 'off'})"
        )

    async def analyze(
        self, content: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze MCP tool source code for docstring/behavior mismatches.

        Args:
            content: File path to Python file/directory OR source code string
            context: Analysis context with tool_name, file_path, etc.

        Returns:
            List of SecurityFinding objects for detected mismatches
        """
        try:
            all_findings = []

            # Check if content is a directory
            if os.path.isdir(content):
                self.logger.debug(f"Scanning directory: {content}")
                python_files = self._find_python_files(content)
                self.logger.debug(
                    f"Found {len(python_files)} Python file(s) to analyze"
                )

                # Build cross-file analyzer for the entire directory
                cross_file_analyzer = CallGraphAnalyzer()
                total_size = 0
                for py_file in python_files:
                    try:
                        # Check file size before loading (configurable via constants)
                        file_size = os.path.getsize(py_file)
                        total_size += file_size

                        if file_size > MCPScannerConstants.MAX_FILE_SIZE_BYTES * 5:
                            self.logger.error(
                                f"Very large file detected, skipping: {py_file} ({file_size:,} bytes)"
                            )
                            continue
                        elif file_size > MCPScannerConstants.MAX_FILE_SIZE_BYTES:
                            self.logger.debug(
                                f"Large file detected: {py_file} ({file_size:,} bytes)"
                            )

                        with open(py_file, "r") as f:
                            source_code = f.read()
                        cross_file_analyzer.add_file(Path(py_file), source_code)
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to add file {py_file} to cross-file analyzer: {e}"
                        )

                # Log total directory size
                self.logger.debug(
                    f"Total directory size: {total_size:,} bytes across {len(python_files)} files"
                )
                if total_size > 10_000_000:  # 10MB
                    self.logger.warning(
                        f"Detected large codebase ({total_size:,} bytes). Analysis performance may be affected."
                    )

                # Build the call graph
                call_graph = cross_file_analyzer.build_call_graph()
                self.logger.debug(
                    f"Built call graph with {len(call_graph.functions)} functions"
                )

                # Analyze each file with cross-file context
                for py_file in python_files:
                    self.logger.debug(f"Analyzing file: {py_file}")
                    file_findings = await self._analyze_file(
                        py_file, context, cross_file_analyzer
                    )
                    all_findings.extend(file_findings)

            # Check if content is a single file
            elif os.path.isfile(content):
                # Build call graph even for single file to track method calls
                cross_file_analyzer = CallGraphAnalyzer()
                try:
                    with open(content, "r") as f:
                        source_code = f.read()
                    cross_file_analyzer.add_file(Path(content), source_code)
                    call_graph = cross_file_analyzer.build_call_graph()
                    self.logger.debug(
                        f"Built call graph with {len(call_graph.functions)} functions"
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
                # Try to build call graph even for source code strings if we can infer structure
                cross_file_analyzer = None
                try:
                    # Create a temporary path for the source code
                    temp_path = Path(context.get("file_path", "inline_code.py"))
                    cross_file_analyzer = CallGraphAnalyzer()
                    cross_file_analyzer.add_file(temp_path, content)
                    call_graph = cross_file_analyzer.build_call_graph()
                    self.logger.debug(
                        f"Built call graph for inline source with {len(call_graph.functions)} functions"
                    )
                    context["cross_file_analyzer"] = cross_file_analyzer
                except Exception as e:
                    self.logger.debug(
                        f"Could not build call graph for inline source: {e}"
                    )

                all_findings = await self._analyze_source_code(content, context)

            self.logger.debug(
                f"Behavioural analysis complete: {len(all_findings)} finding(s) detected"
            )
            return all_findings

        except Exception as e:
            self.logger.error(f"Behavioural analysis failed: {e}", exc_info=True)
            return []

    def _find_python_files(self, directory: str) -> List[str]:
        """Find all Python files in a directory.

        Args:
            directory: Directory path to search

        Returns:
            List of Python file paths
        """
        python_files = []
        path = Path(directory)

        # Recursively find all .py files
        for py_file in path.rglob("*.py"):
            # Skip __pycache__ and hidden directories
            if "__pycache__" not in str(py_file) and not any(
                part.startswith(".") for part in py_file.parts
            ):
                python_files.append(str(py_file))

        return sorted(python_files)

    async def _analyze_file(
        self,
        file_path: str,
        context: Dict[str, Any],
        cross_file_analyzer: Optional[CallGraphAnalyzer] = None,
    ) -> List[SecurityFinding]:
        """Analyze a single Python file.

        Args:
            file_path: Path to Python file
            context: Analysis context
            cross_file_analyzer: Optional cross-file analyzer for tracking imports

        Returns:
            List of SecurityFinding objects
        """
        try:
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

            return findings

        except Exception as e:
            self.logger.error(f"Failed to analyze {file_path}: {e}")
            return []

    async def _analyze_source_code(
        self, source_code: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze Python source code for MCP docstring mismatches.

        Phase 1: Run deterministic rules on FunctionContext (always).
        Phase 2: Run policy checks (if configured).
        Phase 3: Optionally fall back to LLM alignment check (if enabled
                  and no HIGH-severity deterministic finding was produced).

        Args:
            source_code: Python source code to analyze
            context: Analysis context with file_path

        Returns:
            List of security findings
        """
        file_path = context.get("file_path", "unknown")
        findings = []

        try:
            # Use context extractor for complete analysis
            extractor = ContextExtractor(source_code, file_path)
            mcp_contexts = extractor.extract_mcp_function_contexts()

            if not mcp_contexts:
                self.logger.debug(f"No MCP functions found in {file_path}")
                return findings

            self.logger.debug(f"Found {len(mcp_contexts)} MCP functions in {file_path}")

            # Enrich with cross-file context if available
            if context.get("cross_file_analyzer"):
                for func_context in mcp_contexts:
                    self._enrich_with_cross_file_context(
                        func_context, file_path, context["cross_file_analyzer"]
                    )

            # Analyze each MCP entry point
            for func_context in mcp_contexts:
                # --- Phase 1: Deterministic rules ---
                det_matches = self._deterministic.classify(func_context)

                has_high_deterministic = False
                for match in det_matches:
                    finding = self._create_deterministic_finding(
                        match, func_context, file_path
                    )
                    if finding:
                        findings.append(finding)
                        if match.severity == "HIGH":
                            has_high_deterministic = True

                # --- Phase 2: Policy checks ---
                policy_findings = self._run_policy_checks(func_context, file_path)
                findings.extend(policy_findings)

                # --- Phase 3: LLM fallback (optional) ---
                if self._use_llm_fallback and not has_high_deterministic:
                    # Check function source size (configurable via constants)
                    func_source_size = (
                        len(func_context.source)
                        if hasattr(func_context, "source")
                        else 0
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

                    result = await self.alignment_orchestrator.check_alignment(
                        func_context
                    )

                    if result:
                        analysis, ctx = result
                        finding = self._create_security_finding(
                            analysis, ctx, file_path
                        )
                        if finding:
                            findings.append(finding)

        except Exception as e:
            self.logger.error(f"Analysis failed for {file_path}: {e}", exc_info=True)

        return findings

    def _create_deterministic_finding(
        self, match: RuleMatch, func_context, file_path: str
    ) -> Optional[SecurityFinding]:
        """Create a SecurityFinding from a deterministic RuleMatch.

        Args:
            match: The rule match result
            func_context: FunctionContext for the matched function
            file_path: Source file path

        Returns:
            SecurityFinding or None
        """
        try:
            threat_info = ThreatMapping.get_threat_mapping(
                "behavioral", match.threat_name
            )
        except ValueError:
            self.logger.warning(
                f"No threat mapping for deterministic rule {match.rule_id}: "
                f"{match.threat_name}"
            )
            return None

        evidence_str = "; ".join(match.evidence[:5])
        line_info = f"Line {func_context.line_number}: "
        summary = (
            f"{line_info}[{match.rule_id}] {match.threat_name} — {evidence_str}"
        )

        # Enrich with data classification for exfiltration findings
        data_classification = None
        if "EXFILTRATION" in match.threat_name:
            variable_names = [
                a.get("variable", "") for a in func_context.assignments
            ]
            param_names = [p.get("name", "") for p in func_context.parameters]
            classification = self._data_classifier.classify_from_context(
                string_literals=func_context.string_literals,
                env_var_access=func_context.env_var_access,
                parameter_names=param_names,
                variable_names=variable_names,
            )
            if classification.has_sensitive_data:
                data_classification = {
                    "categories": sorted(classification.categories),
                    "evidence": classification.evidence[:5],
                }

        return SecurityFinding(
            severity=match.severity,
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
                "threat_name": match.threat_name,
                "threat_type": match.threat_name,
                "rule_id": match.rule_id,
                "deterministic": True,
                "evidence": match.evidence,
                "data_classification": data_classification,
                "aitech": threat_info["aitech"],
                "aitech_name": threat_info["aitech_name"],
                "aisubtech": threat_info["aisubtech"],
                "aisubtech_name": threat_info["aisubtech_name"],
                "taxonomy_description": threat_info["description"],
            },
        )

    def _run_policy_checks(
        self, func_context, file_path: str
    ) -> List[SecurityFinding]:
        """Run network and filesystem policy checks on a function context.

        Args:
            func_context: FunctionContext with string literals, etc.
            file_path: Source file path

        Returns:
            List of policy violation findings
        """
        findings = []

        # Network egress policy
        if self._network_policy.is_configured:
            for violation in self._network_policy.check_strings(
                func_context.string_literals
            ):
                findings.append(
                    SecurityFinding(
                        severity=violation.severity,
                        summary=(
                            f"Line {func_context.line_number}: Network policy violation "
                            f"— {violation.reason}: {violation.destination}"
                        ),
                        analyzer="Behavioral",
                        threat_category="UNAUTHORIZED OR UNSOLICITED NETWORK ACCESS",
                        details={
                            "function_name": func_context.name,
                            "source_file": file_path,
                            "policy_type": "network_egress",
                            "destination": violation.destination,
                            "reason": violation.reason,
                            "deterministic": True,
                        },
                    )
                )

        # Filesystem boundary policy
        if self._filesystem_policy.is_configured:
            for violation in self._filesystem_policy.check_strings(
                func_context.string_literals
            ):
                findings.append(
                    SecurityFinding(
                        severity=violation.severity,
                        summary=(
                            f"Line {func_context.line_number}: Filesystem policy violation "
                            f"— {violation.reason}: {violation.path}"
                        ),
                        analyzer="Behavioral",
                        threat_category="UNAUTHORIZED OR UNSOLICITED SYSTEM ACCESS",
                        details={
                            "function_name": func_context.name,
                            "source_file": file_path,
                            "policy_type": "filesystem_boundary",
                            "path": violation.path,
                            "reason": violation.reason,
                            "deterministic": True,
                        },
                    )
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

            # Get threat mapping from taxonomy
            try:
                threat_info = ThreatMapping.get_threat_mapping(
                    "behavioral", threat_name
                )
            except ValueError as e:
                self.logger.warning(f"Unknown threat name '{threat_name}': {e}")
                return None

            # Use severity from centralized threat mapping only
            severity = threat_info["severity"]

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
        self, func_context, file_path: str, call_graph_analyzer
    ) -> None:
        """Enrich function context with cross-file analysis data.

        Args:
            func_context: FunctionContext to enrich
            file_path: Source file path
            call_graph_analyzer: CallGraphAnalyzer instance
        """
        try:
            # Build full function name for call graph lookup
            full_func_name = f"{file_path}::{func_context.name}"

            # Get all reachable functions from this entry point
            reachable = call_graph_analyzer.get_reachable_functions(full_func_name)
            if reachable:
                func_context.reachable_functions = reachable

            # Analyze parameter flow across files if parameters exist
            if func_context.parameters:
                param_names = [
                    p.get("name") for p in func_context.parameters if p.get("name")
                ]
                if param_names:
                    flow_info = call_graph_analyzer.analyze_parameter_flow_across_files(
                        full_func_name, param_names
                    )

                    # Add cross-file flow information
                    if flow_info.get("cross_file_flows"):
                        func_context.cross_file_calls = flow_info["cross_file_flows"]

                    # Store summary in dataflow
                    func_context.dataflow_summary["cross_file_analysis"] = {
                        "total_reachable": len(reachable),
                        "files_involved": flow_info.get("total_files_involved", 0),
                        "param_influenced_functions": len(
                            flow_info.get("param_influenced_functions", [])
                        ),
                    }

        except Exception as e:
            self.logger.warning(f"Failed to enrich with cross-file context: {e}")
