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

"""Behavioral Code Analyzer for MCP Scanner - Multi-Language Support.

This analyzer detects mismatches between MCP tool docstrings/descriptions and their actual 
code behavior using deep code analysis and LLM-based comparison.

Supports: Python, JavaScript, TypeScript, Java, Kotlin, Go, Swift, C#

This analyzer:
1. Identifies MCP decorator usage (@mcp.tool, @tool, [McpServerTool], etc.)
2. Extracts comprehensive code context (dataflow, taint, constants)
3. Analyzes actual code behavior using full AST + dataflow analysis
4. Uses LLM to detect semantic mismatches between description and implementation
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ....config.config import Config
from ....threats.threats import ThreatMapping
from ...static_analysis.context_extractor import ContextExtractor, FunctionContext
from ...static_analysis.interprocedural.call_graph_analyzer import CallGraphAnalyzer
from ...static_analysis.language_detector import (
    Language,
    detect_language,
    get_parser_for_language,
    get_normalizer_for_language,
    get_mcp_functions,
)
from ...static_analysis.unified_ast import NodeType
from ...static_analysis.cfg.unified_cfg_builder import UnifiedCFGBuilder
from ...static_analysis.dataflow.unified_forward_analysis import UnifiedForwardDataflowAnalysis
from ..base import BaseAnalyzer, SecurityFinding
from .alignment import AlignmentOrchestrator


class BehavioralCodeAnalyzer(BaseAnalyzer):
    """Analyzer that detects docstring/behavior mismatches in MCP tool source code.
    
    Supports 8 languages: Python, JavaScript, TypeScript, Java, Kotlin, Go, Swift, C#
    
    This analyzer:
    1. Extracts MCP tool source code from the server
    2. Performs deep dataflow analysis using the behavioural engine
    3. Uses LLM to compare docstring claims vs actual behavior
    4. Detects hidden behaviors like data exfiltration
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
        
        self.logger.info("BehavioralCodeAnalyzer initialized with alignment verification")

    async def analyze(
        self, content: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze MCP tool source code for docstring/behavior mismatches.
        
        Args:
            content: File path to source file/directory OR source code string
            context: Analysis context with tool_name, file_path, etc.
            
        Returns:
            List of SecurityFinding objects for detected mismatches
        """
        try:
            all_findings = []
            
            # Check if content is a directory
            if os.path.isdir(content):
                self.logger.info(f"Scanning directory: {content}")
                source_files = self._find_source_files(content)
                self.logger.info(f"Found {len(source_files)} source file(s) to analyze")
                
                # Build cross-file analyzer for the entire directory
                cross_file_analyzer = CallGraphAnalyzer()
                for source_file in source_files:
                    try:
                        with open(source_file, 'r') as f:
                            source_code = f.read()
                        cross_file_analyzer.add_file(Path(source_file), source_code)
                    except Exception as e:
                        self.logger.warning(f"Failed to add file {source_file} to cross-file analyzer: {e}")
                
                # Build the call graph
                call_graph = cross_file_analyzer.build_call_graph()
                self.logger.info(f"Built call graph with {len(call_graph.functions)} functions")
                
                # Analyze each file with cross-file context
                for source_file in source_files:
                    self.logger.info(f"Analyzing file: {source_file}")
                    file_findings = await self._analyze_file(source_file, context, cross_file_analyzer)
                    all_findings.extend(file_findings)
                    
            # Check if content is a single file
            elif os.path.isfile(content):
                # Build call graph even for single file to track method calls
                cross_file_analyzer = CallGraphAnalyzer()
                try:
                    with open(content, 'r') as f:
                        source_code = f.read()
                    cross_file_analyzer.add_file(Path(content), source_code)
                    call_graph = cross_file_analyzer.build_call_graph()
                    self.logger.info(f"Built call graph with {len(call_graph.functions)} functions")
                except Exception as e:
                    self.logger.warning(f"Failed to build call graph for {content}: {e}")
                    cross_file_analyzer = None
                
                all_findings = await self._analyze_file(content, context, cross_file_analyzer)
                
            else:
                # Content is source code string
                all_findings = await self._analyze_source_code(content, context)
            
            self.logger.info(
                f"Behavioural analysis complete: {len(all_findings)} finding(s) detected"
            )
            return all_findings
            
        except Exception as e:
            self.logger.error(f"Behavioural analysis failed: {e}", exc_info=True)
            return []
    
    def _find_source_files(self, directory: str) -> List[str]:
        """Find all supported source files in a directory.
        
        Supports: Python (.py), JavaScript (.js), TypeScript (.ts, .tsx),
                  Java (.java), Kotlin (.kt, .kts), Go (.go), Swift (.swift), C# (.cs), Ruby (.rb), Rust (.rs)
        
        Args:
            directory: Directory path to search
            
        Returns:
            List of source file paths
        """
        source_files = []
        path = Path(directory)
        
        # Supported extensions
        extensions = ['*.py', '*.js', '*.ts', '*.tsx', '*.java', '*.kt', '*.kts', '*.go', '*.swift', '*.cs', '*.rb', '*.rs']
        
        for ext in extensions:
            for source_file in path.rglob(ext):
                # Skip __pycache__, node_modules, and hidden directories
                if ("__pycache__" not in str(source_file) and 
                    "node_modules" not in str(source_file) and
                    not any(part.startswith(".") for part in source_file.parts)):
                    source_files.append(str(source_file))
        
        return sorted(source_files)
    
    async def _analyze_file(
        self, 
        file_path: str, 
        context: Dict[str, Any],
        cross_file_analyzer: Optional[CallGraphAnalyzer] = None
    ) -> List[SecurityFinding]:
        """Analyze a single source file (supports multiple languages).
        
        Args:
            file_path: Path to source file
            context: Analysis context
            cross_file_analyzer: Optional cross-file analyzer for tracking imports
            
        Returns:
            List of SecurityFinding objects
        """
        try:
            # Detect language
            language = detect_language(Path(file_path))
            
            if language == Language.UNKNOWN:
                self.logger.warning(f"Unsupported file type: {file_path}")
                return []
            
            self.logger.info(f"Detected language: {language.value} for {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            file_context = context.copy()
            file_context['file_path'] = file_path
            file_context['language'] = language
            file_context['cross_file_analyzer'] = cross_file_analyzer if language == Language.PYTHON else None
            
            findings = await self._analyze_source_code(source_code, file_context)
            
            # Tag findings with file path and language
            for finding in findings:
                if finding.details:
                    finding.details['source_file'] = file_path
                    finding.details['language'] = language.value
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Failed to analyze {file_path}: {e}")
            return []
    
    async def _analyze_source_code(self, source_code: str, context: Dict[str, Any]) -> List[SecurityFinding]:
        """Analyze source code for MCP docstring/description mismatches.
        
        Supports: Python, JavaScript, TypeScript, Java, Kotlin, Go, Swift, C#
        
        Args:
            source_code: Source code to analyze
            context: Analysis context with file_path and language
            
        Returns:
            List of security findings
        """
        file_path = context.get("file_path", "unknown")
        language = context.get("language", Language.PYTHON)
        findings = []
        
        try:
            # Route to language-specific analyzer
            if language == Language.PYTHON:
                # Use context extractor for Python (legacy path with full features)
                extractor = ContextExtractor(source_code, file_path)
                mcp_contexts = extractor.extract_mcp_function_contexts()
                
                if not mcp_contexts:
                    self.logger.debug(f"No MCP functions found in {file_path}")
                    return findings
                
                self.logger.info(f"Found {len(mcp_contexts)} MCP functions in {file_path}")
                
                # Enrich with cross-file context if available
                if context.get('cross_file_analyzer'):
                    for func_context in mcp_contexts:
                        self._enrich_with_cross_file_context(
                            func_context, 
                            file_path, 
                            context['cross_file_analyzer']
                        )
                
                # Analyze each MCP entry point using alignment orchestrator
                for func_context in mcp_contexts:
                    result = await self.alignment_orchestrator.check_alignment(func_context)
                    
                    if result:
                        analysis, ctx = result
                        finding = self._create_security_finding(analysis, ctx, file_path)
                        if finding:
                            findings.append(finding)
            
            else:
                # Use unified infrastructure for other languages
                findings = await self._analyze_unified_language(source_code, file_path, language)
        
        except Exception as e:
            self.logger.error(f"Analysis failed for {file_path}: {e}", exc_info=True)
        
        return findings
    
    async def _analyze_unified_language(
        self,
        source_code: str,
        file_path: str,
        language: 'Language'
    ) -> List[SecurityFinding]:
        """Analyze non-Python languages using unified infrastructure.
        
        Supports: JavaScript, TypeScript, Java, Kotlin, Go, Swift, C#
        
        Args:
            source_code: Source code to analyze
            file_path: Path to source file
            language: Detected language
            
        Returns:
            List of security findings
        """
        findings = []
        
        try:
            # Parse source code using language-specific parser
            parser = get_parser_for_language(language, Path(file_path), source_code)
            ast = parser.parse()
            
            if not ast:
                self.logger.warning(f"Failed to parse {file_path}")
                return findings
            
            # Find MCP-decorated functions
            mcp_functions = get_mcp_functions(language, parser, ast)
            
            if not mcp_functions:
                self.logger.debug(f"No MCP functions found in {file_path}")
                return findings
            
            self.logger.info(f"Found {len(mcp_functions)} MCP function(s) in {file_path}")
            
            # Get normalizer for this language
            normalizer = get_normalizer_for_language(language, parser)
            
            # Analyze each MCP function
            for func_node in mcp_functions:
                try:
                    # Normalize to unified AST
                    unified_func = normalizer.normalize_function(func_node)
                    
                    # Extract docstring/comment
                    docstring = parser.extract_comment(func_node) if hasattr(parser, 'extract_comment') else None
                    
                    # Build CFG
                    # Perform dataflow analysis
                    dataflow_analyzer = UnifiedForwardDataflowAnalysis(unified_func, unified_func.parameters)
                    dataflow_result = dataflow_analyzer.analyze_forward_flows()
                    
                    # Build function context for LLM analysis
                    func_context = self._build_function_context(
                        unified_func,
                        docstring,
                        dataflow_result,
                        file_path,
                        language
                    )
                    
                    # Log analysis details
                    self.logger.info(f"\n{'='*80}")
                    self.logger.info(f"{language.value.upper()} FUNCTION FULL ANALYSIS FOR: {unified_func.name}")
                    self.logger.info(f"{'='*80}")
                    self.logger.info(f"Parameters: {unified_func.parameters}")
                    self.logger.info(f"Doc: {docstring[:100] if docstring else 'None'}")
                    self.logger.info(f"Line number: {unified_func.location.line if unified_func.location else 'unknown'}")
                    self.logger.info(f"Is async: {unified_func.is_async}")
                    self.logger.info(f"Return type: {unified_func.return_type}")
                    
                    # Log function calls
                    if func_context.function_calls:
                        self.logger.info(f"\nFunction calls ({len(func_context.function_calls)} total):")
                        for i, call in enumerate(func_context.function_calls[:20], 1):
                            self.logger.info(f"  {i}. {call}")
                    
                    # Log parameter flows
                    if func_context.parameter_flows:
                        self.logger.info(f"\nParameter flows ({len(func_context.parameter_flows)} total):")
                        for i, flow in enumerate(func_context.parameter_flows, 1):
                            self.logger.info(f"  Flow {i}:")
                            self.logger.info(f"    - Parameter: {flow.get('parameter')}")
                            self.logger.info(f"    - Operations: {flow.get('operations', [])}")
                            self.logger.info(f"    - Reaches calls: {flow.get('reaches_calls', [])}")
                            self.logger.info(f"    - Reaches returns: {flow.get('reaches_returns')}")
                            self.logger.info(f"    - Reaches external: {flow.get('reaches_external')}")
                    
                    # Log assignments
                    if func_context.assignments:
                        self.logger.info(f"\nAssignments: {func_context.assignments}")
                    
                    self.logger.info(f"{'='*80}\n")
                    
                    # Check alignment using LLM
                    result = await self.alignment_orchestrator.check_alignment(func_context)
                    
                    if result:
                        analysis, ctx = result
                        finding = self._create_security_finding(analysis, ctx, file_path)
                        if finding:
                            findings.append(finding)
                
                except Exception as e:
                    self.logger.error(f"Failed to analyze function in {file_path}: {e}", exc_info=True)
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to analyze {language.value} file {file_path}: {e}", exc_info=True)
        
        return findings
    
    def _build_function_context(
        self,
        unified_func,
        docstring,
        dataflow_result,
        file_path: str,
        language: 'Language'
    ):
        """Build function context from unified AST and dataflow analysis.
        
        Args:
            unified_func: Unified AST function node
            docstring: Function documentation
            dataflow_result: Dataflow analysis result
            file_path: Source file path
            language: Programming language
            
        Returns:
            FunctionContext object for LLM analysis
        """
        # Extract function calls from AST with source code context
        function_calls = []
        for node in unified_func.walk():
            if node.type == NodeType.CALL:
                call_info = {
                    'type': 'function_call',
                    'function': node.name,
                    'line': node.location.line if node.location else 0
                }
                # Include source code if available (for non-Python languages)
                if node.metadata and 'source_code' in node.metadata:
                    call_info['source'] = node.metadata['source_code']
                function_calls.append(call_info)
        
        # Extract assignments
        assignments = []
        for node in unified_func.walk():
            if node.type == NodeType.ASSIGNMENT:
                assignments.append({
                    'type': 'assignment',
                    'target': node.name,
                    'line': node.location.line if node.location else 0
                })
        
        # Extract string literals from function metadata (for non-Python languages)
        string_literals = []
        if unified_func.metadata and 'string_literals' in unified_func.metadata:
            string_literals = unified_func.metadata['string_literals']
        
        # Build parameter flows from dataflow analysis
        parameter_flows = []
        if dataflow_result:
            # Use the ACTUAL dataflow results from UnifiedForwardDataflowAnalysis
            for flow_path in dataflow_result:
                flow = {
                    'parameter': flow_path.parameter_name,
                    'operations': [op for op in flow_path.operations] if hasattr(flow_path, 'operations') else [],
                    'reaches_calls': flow_path.reaches_calls if hasattr(flow_path, 'reaches_calls') else [],
                    'reaches_returns': flow_path.reaches_returns if hasattr(flow_path, 'reaches_returns') else False,
                    'reaches_external': flow_path.reaches_external if hasattr(flow_path, 'reaches_external') else False
                }
                parameter_flows.append(flow)
        
        # Create function context
        func_context = FunctionContext(
            name=unified_func.name or "<unknown>",
            parameters=unified_func.parameters,
            docstring=docstring,
            line_number=unified_func.location.line if unified_func.location else 0,
            decorator_types=[],
            return_type=unified_func.return_type,
            parameter_flows=parameter_flows,
            variable_dependencies={},
            imports=[],
            function_calls=function_calls,
            assignments=assignments,
            control_flow={},
            cross_file_calls=[],
            reachable_functions=[],
            constants={},
            string_literals=string_literals,  # Include extracted string literals
            return_expressions=[],
            exception_handlers=[],
            env_var_access=[],
            global_writes=[],
            attribute_access=[],
            has_file_operations=False,
            has_network_operations=False,
            has_subprocess_calls=False,
            has_eval_exec=False,
            has_dangerous_imports=False,
            dataflow_summary={'language': language.value}
        )
        
        return func_context
    
    def _create_security_finding(
        self,
        analysis: Dict[str, Any],
        func_context,
        file_path: str
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
                self.logger.warning(f"No threat_name in analysis for {func_context.name}")
                return None
            
            # Get threat mapping from taxonomy
            try:
                threat_info = ThreatMapping.get_threat_mapping("behavioral", threat_name)
            except ValueError as e:
                self.logger.warning(f"Unknown threat name '{threat_name}': {e}")
                return None
            
            # Use LLM severity if available, otherwise use mapping default
            severity = analysis.get("severity", threat_info["severity"]).upper()
            
            # Build comprehensive summary
            summary = f"Line {func_context.line_number}: {threat_name} - "
            summary += f"Description claims: '{analysis.get('description_claims', 'N/A')}' | "
            summary += f"Actual behavior: {analysis.get('actual_behavior', 'N/A')}"
            
            # Create finding with MCP Taxonomy information
            finding = SecurityFinding(
                severity=severity,
                summary=summary,
                analyzer="behavioral_analyzer",
                threat_category=threat_info["scanner_category"],
                details={
                    "function_name": func_context.name,
                    "line_number": func_context.line_number,
                    "mismatch_type": analysis.get("mismatch_type", "unknown"),
                    "confidence": analysis.get("confidence", "MEDIUM"),
                    "security_implications": analysis.get("security_implications", ""),
                    "dataflow_evidence": analysis.get("dataflow_evidence", ""),
                    "full_analysis": analysis,
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
        call_graph_analyzer
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
                param_names = [p.get('name') for p in func_context.parameters if p.get('name')]
                if param_names:
                    flow_info = call_graph_analyzer.analyze_parameter_flow_across_files(
                        full_func_name, 
                        param_names
                    )
                    
                    # Add cross-file flow information
                    if flow_info.get('cross_file_flows'):
                        func_context.cross_file_calls = flow_info['cross_file_flows']
                    
                    # Store summary in dataflow
                    func_context.dataflow_summary['cross_file_analysis'] = {
                        'total_reachable': len(reachable),
                        'files_involved': flow_info.get('total_files_involved', 0),
                        'param_influenced_functions': len(flow_info.get('param_influenced_functions', []))
                    }
        
        except Exception as e:
            self.logger.warning(f"Failed to enrich with cross-file context: {e}")
