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

"""Behavioural Analyzer for MCP Scanner.

This analyzer detects mismatches between MCP tool docstrings and their actual 
code behavior using deep code analysis and LLM-based comparison.

This analyzer:
1. Identifies MCP decorator usage (@mcp.tool, @mcp.prompt, @mcp.resource)
2. Extracts comprehensive code context (dataflow, taint, constants)
3. Analyzes actual code behavior using full AST + dataflow analysis
4. Uses LLM to detect semantic mismatches between description and implementation
"""

import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

from litellm import acompletion

from ...config.config import Config
from ...config.constants import MCPScannerConstants
from ...behavioural.context_extractor import CodeContextExtractor, FunctionContext
from ...behavioural.analysis.cross_file import CrossFileAnalyzer
from .base import BaseAnalyzer, SecurityFinding


class BehaviouralAnalyzer(BaseAnalyzer):
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
        """Initialize the BehaviouralAnalyzer.
        
        Args:
            config: Configuration containing LLM credentials
            
        Raises:
            ValueError: If LLM provider API key is not configured
        """
        super().__init__(name="Behavioural")
        self._config = config
        
        if not hasattr(config, "llm_provider_api_key") or not config.llm_provider_api_key:
            raise ValueError("LLM provider API key is required for Behavioural analyzer")
        
        # Store configuration for per-request usage instead of global settings
        # This avoids conflicts when multiple analyzers are used
        self._api_key = config.llm_provider_api_key
        self._base_url = config.llm_base_url
        self._api_version = config.llm_api_version
        
        # Get model configuration from config
        self._model = config.llm_model
        self._max_tokens = config.llm_max_tokens
        self._temperature = config.llm_temperature
        
        # Load prompt template
        self._prompt_template = self._load_prompt()
        
        self.logger.info("BehaviouralAnalyzer initialized with LLM-based analysis")

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
                self.logger.info(f"Scanning directory: {content}")
                python_files = self._find_python_files(content)
                self.logger.info(f"Found {len(python_files)} Python file(s) to analyze")
                
                # Build cross-file analyzer for the entire directory
                cross_file_analyzer = CrossFileAnalyzer()
                for py_file in python_files:
                    try:
                        with open(py_file, 'r') as f:
                            source_code = f.read()
                        cross_file_analyzer.add_file(Path(py_file), source_code)
                    except Exception as e:
                        self.logger.warning(f"Failed to add file {py_file} to cross-file analyzer: {e}")
                
                # Build the call graph
                call_graph = cross_file_analyzer.build_call_graph()
                self.logger.info(f"Built call graph with {len(call_graph.functions)} functions")
                
                # Analyze each file with cross-file context
                for py_file in python_files:
                    self.logger.info(f"Analyzing file: {py_file}")
                    file_findings = await self._analyze_file(py_file, context, cross_file_analyzer)
                    all_findings.extend(file_findings)
                    
            # Check if content is a single file
            elif os.path.isfile(content):
                # Build call graph even for single file to track method calls
                cross_file_analyzer = CrossFileAnalyzer()
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
        cross_file_analyzer: Optional[CrossFileAnalyzer] = None
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
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            file_context = context.copy()
            file_context['file_path'] = file_path
            file_context['cross_file_analyzer'] = cross_file_analyzer
            
            findings = await self._analyze_source_code(source_code, file_context)
            
            # Tag findings with file path
            for finding in findings:
                if finding.details:
                    finding.details['source_file'] = file_path
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Failed to analyze {file_path}: {e}")
            return []
    
    async def _analyze_source_code(self, source_code: str, context: Dict[str, Any]) -> List[SecurityFinding]:
        """Analyze Python source code for MCP docstring mismatches.
        
        Args:
            source_code: Python source code to analyze
            context: Analysis context with file_path
            
        Returns:
            List of security findings
        """
        file_path = context.get("file_path", "unknown")
        findings = []
        
        try:
            # Get cross-file analyzer if available
            cross_file_analyzer = context.get('cross_file_analyzer')
            
            # Use behavioural context extractor for complete analysis
            # Pass call graph for inter-procedural dataflow tracking
            call_graph = cross_file_analyzer.call_graph if cross_file_analyzer else None
            extractor = CodeContextExtractor(source_code, file_path, call_graph=call_graph)
            mcp_contexts = extractor.extract_mcp_function_contexts()
            
            if not mcp_contexts:
                self.logger.debug(f"No MCP functions found in {file_path}")
                return findings
            
            self.logger.info(f"Found {len(mcp_contexts)} MCP functions in {file_path}")
            
            # Enrich with cross-file context if available
            if cross_file_analyzer:
                for func_context in mcp_contexts:
                    self._enrich_with_cross_file_context(func_context, file_path, cross_file_analyzer)
            
            # Analyze each MCP entry point
            for func_context in mcp_contexts:
                analysis = await self._analyze_mcp_entrypoint_with_llm(func_context)
                
                if not analysis or not analysis.get("mismatch_detected"):
                    continue
                
                # Create security finding
                severity = analysis.get("severity", "MEDIUM")
                
                # Format threat summary to show comparison: Claims vs Reality
                description_claims = analysis.get("description_claims", "")
                actual_behavior = analysis.get("actual_behavior", "")
                
                # Include line number in the summary for easy reference
                line_info = f"Line {func_context.line_number}: "
                
                if description_claims and actual_behavior:
                    threat_summary = f"{line_info}Description claims: '{description_claims}' | Actual behavior: {actual_behavior}"
                else:
                    # Fallback to security implications if comparison fields are missing
                    threat_summary = f"{line_info}{analysis.get('security_implications', f'Mismatch detected in {func_context.name}')}"
                
                finding = SecurityFinding(
                    severity=severity,
                    summary=threat_summary,
                    analyzer="Behavioural",
                    threat_category="DESCRIPTION_MISMATCH",
                    details={
                        "function_name": func_context.name,
                        "decorator_type": func_context.decorator_types[0] if func_context.decorator_types else "unknown",
                        "line_number": func_context.line_number,
                        "mismatch_type": analysis.get("mismatch_type"),
                        "description_claims": description_claims,
                        "actual_behavior": actual_behavior,
                        "security_implications": analysis.get("security_implications"),
                        "confidence": analysis.get("confidence"),
                        "dataflow_evidence": analysis.get("dataflow_evidence"),
                        "parameter_flows": func_context.parameter_flows,
                    },
                )
                
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Analysis failed for {file_path}: {e}", exc_info=True)
        
        return findings
    
    async def _analyze_mcp_entrypoint_with_llm(self, func_context: FunctionContext) -> Optional[Dict[str, Any]]:
        """Use LLM to analyze MCP entry point with complete dataflow context.
        
        This is the reversed approach:
        - MCP entry points are sources (parameters are untrusted)
        - We trace ALL paths from parameters
        - LLM analyzes complete behavior vs description
        
        Args:
            func_context: Complete function context with dataflow analysis
            
        Returns:
            Analysis result dict or None if no mismatch
        """
        prompt = self._create_comprehensive_analysis_prompt(func_context)
        
        try:
            request_params = {
                "model": self._model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security expert analyzing MCP tools. You receive complete dataflow, taint analysis, and code context. Analyze if the docstring accurately describes what the code actually does. Respond only with valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
                "timeout": 30.0,
                "api_key": self._api_key,
            }
            
            if self._base_url:
                request_params["api_base"] = self._base_url
            if self._api_version:
                request_params["api_version"] = self._api_version
            
            response = await acompletion(**request_params)
            content = response.choices[0].message.content
            
            return self._parse_llm_response(content)
            
        except Exception as e:
            self.logger.error(f"LLM analysis failed for {func_context.name}: {e}")
            return None
    
    def _enrich_with_cross_file_context(
        self, 
        func_context: FunctionContext, 
        file_path: str,
        cross_file_analyzer: CrossFileAnalyzer
    ) -> None:
        """Enrich function context with cross-file analysis data.
        
        Args:
            func_context: Function context to enrich
            file_path: Path to the file containing the function
            cross_file_analyzer: Cross-file analyzer instance
        """
        try:
            # Build full function name
            full_func_name = f"{file_path}::{func_context.name}"
            
            # Get reachable functions from this entry point
            reachable = cross_file_analyzer.get_reachable_functions(full_func_name)
            func_context.reachable_functions = reachable
            
            # Get cross-file calls with transitive chains
            cross_file_calls = []
            for caller, callee in cross_file_analyzer.call_graph.calls:
                if caller == full_func_name:
                    caller_file = caller.split("::")[0] if "::" in caller else ""
                    callee_file = callee.split("::")[0] if "::" in callee else ""
                    
                    # Check if it's a cross-file call
                    if caller_file and callee_file and caller_file != callee_file:
                        callee_func_name = callee.split("::")[-1] if "::" in callee else callee
                        
                        # Build transitive call chain from this callee (deep traversal)
                        call_chain = self._build_call_chain(callee, cross_file_analyzer, max_depth=10)
                        
                        cross_file_calls.append({
                            "function": callee_func_name,
                            "file": callee_file,
                            "full_name": callee,
                            "call_chain": call_chain
                        })
            
            func_context.cross_file_calls = cross_file_calls
            
            if cross_file_calls:
                self.logger.info(f"Function '{func_context.name}' calls {len(cross_file_calls)} function(s) from other files")
                
        except Exception as e:
            self.logger.warning(f"Failed to enrich cross-file context for {func_context.name}: {e}")
    
    def _build_call_chain(
        self, 
        func_name: str, 
        cross_file_analyzer: CrossFileAnalyzer,
        max_depth: int = 3,
        visited: Optional[set] = None
    ) -> List[Dict[str, Any]]:
        """Build transitive call chain from a function.
        
        Args:
            func_name: Starting function name
            cross_file_analyzer: Cross-file analyzer
            max_depth: Maximum depth to traverse
            visited: Set of already visited functions (to avoid cycles)
            
        Returns:
            List of calls in the chain
        """
        if visited is None:
            visited = set()
        
        if max_depth <= 0 or func_name in visited:
            return []
        
        visited.add(func_name)
        chain = []
        
        # Get direct callees
        callees = cross_file_analyzer.call_graph.get_callees(func_name)
        
        for callee in callees[:10]:  # Limit to 10 to avoid explosion
            callee_func = callee.split("::")[-1] if "::" in callee else callee
            
            # Recursively build chain
            sub_chain = self._build_call_chain(callee, cross_file_analyzer, max_depth - 1, visited.copy())
            
            chain.append({
                "function": callee_func,
                "full_name": callee,
                "calls": sub_chain
            })
        
        return chain
    
    def _format_call_chain(self, chain: List[Dict[str, Any]], indent: int = 0) -> str:
        """Format call chain recursively for display.
        
        Args:
            chain: Call chain to format
            indent: Current indentation level
            
        Returns:
            Formatted call chain string
        """
        result = ""
        for call in chain:
            result += " " * indent + f"└─ {call['function']}()\n"
            if call.get('calls'):
                result += self._format_call_chain(call['calls'], indent + 3)
        return result
    
    def _load_prompt(self) -> str:
        """Load the description mismatch prompt template.
        
        Returns:
            Prompt template string
            
        Raises:
            FileNotFoundError: If the prompt file cannot be found
            IOError: If the prompt file cannot be read
        """
        try:
            prompt_file = MCPScannerConstants.get_prompts_path() / "description_mismatch_prompt.md"
            
            if not prompt_file.is_file():
                raise FileNotFoundError("Prompt file not found: description_mismatch_prompt.md")
            
            return prompt_file.read_text(encoding="utf-8")
            
        except FileNotFoundError:
            self.logger.error("Prompt file not found: description_mismatch_prompt.md")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load prompt description_mismatch_prompt.md: {e}")
            raise IOError(f"Could not load prompt description_mismatch_prompt.md: {e}")
    
    def _create_comprehensive_analysis_prompt(self, ctx: FunctionContext) -> str:
        """Create comprehensive analysis prompt with full dataflow context.
        
        Uses randomized delimiter tags to prevent prompt injection attacks.
        
        Args:
            ctx: Function context with complete analysis
            
        Returns:
            Formatted prompt string
        """
        # Generate random delimiter tags to prevent prompt injection
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"
        
        docstring = ctx.docstring or "No docstring provided"
        
        # Build the analysis content (untrusted input)
        analysis_content = f"""**ENTRY POINT INFORMATION:**
- Function Name: {ctx.name}
- Decorator: {ctx.decorator_types[0] if ctx.decorator_types else 'unknown'}
- Line: {ctx.line_number}
- Docstring/Description: {docstring}



**FUNCTION SIGNATURE:**
- Parameters: {json.dumps(ctx.parameters, indent=2)}
- Return Type: {ctx.return_type or 'Not specified'}

**DATAFLOW ANALYSIS:**
All parameters are treated as untrusted input (MCP entry points receive external data).

Parameter Flow Tracking:
"""
        
        # Add parameter flow tracking (REVERSED APPROACH)
        if ctx.parameter_flows:
            analysis_content += "\n**PARAMETER FLOW TRACKING:**\n"
            for flow in ctx.parameter_flows:
                param_name = flow.get("parameter", "unknown")
                analysis_content += f"\nParameter '{param_name}' flows through:\n"
                
                if flow.get("operations"):
                    analysis_content += f"  Operations ({len(flow['operations'])} total):\n"
                    for op in flow["operations"][:10]:  # Limit to first 10
                        op_type = op.get("type", "unknown")
                        line = op.get("line", 0)
                        if op_type == "assignment":
                            analysis_content += f"    Line {line}: {op.get('target')} = {op.get('value')}\n"
                        elif op_type == "function_call":
                            analysis_content += f"    Line {line}: {op.get('function')}({op.get('argument')})\n"
                        elif op_type == "return":
                            analysis_content += f"    Line {line}: return {op.get('value')}\n"
                
                if flow.get("reaches_calls"):
                    analysis_content += f"  Reaches function calls: {', '.join(flow['reaches_calls'][:10])}\n"
                
                if flow.get("reaches_external"):
                    analysis_content += f"  ⚠️  REACHES EXTERNAL OPERATIONS (file/network/subprocess)\n"
                
                if flow.get("reaches_returns"):
                    analysis_content += f"  Returns to caller\n"
        
        # Add variable dependencies
        if ctx.variable_dependencies:
            analysis_content += "\n**VARIABLE DEPENDENCIES:**\n"
            for var, deps in ctx.variable_dependencies.items():
                analysis_content += f"  {var} depends on: {', '.join(deps)}\n"
        
        # Add function calls
        analysis_content += f"\n**FUNCTION CALLS ({len(ctx.function_calls)} total):**\n"
        for call in ctx.function_calls[:20]:  # Limit to first 20
            analysis_content += f"  Line {call['line']}: {call['name']}({', '.join(call['args'])})\n"
        
        # Add assignments
        if ctx.assignments:
            analysis_content += f"\n**ASSIGNMENTS ({len(ctx.assignments)} total):**\n"
            for assign in ctx.assignments[:15]:  # Limit to first 15
                analysis_content += f"  Line {assign['line']}: {assign['variable']} = {assign['value']}\n"
        
        # Add control flow information
        if ctx.control_flow:
            analysis_content += f"\n**CONTROL FLOW:**\n"
            analysis_content += f"{json.dumps(ctx.control_flow, indent=2)}\n"
        
        # Add cross-file analysis with transitive call chains
        if ctx.cross_file_calls:
            analysis_content += f"\n**CROSS-FILE CALL CHAINS ({len(ctx.cross_file_calls)} calls to other files):**\n"
            analysis_content += "⚠️  This function calls functions from other files. Full call chains shown:\n\n"
            for call in ctx.cross_file_calls[:10]:
                analysis_content += f"  {call['function']}() in {call['file']}\n"
                # Show transitive calls
                if call.get('call_chain'):
                    analysis_content += self._format_call_chain(call['call_chain'], indent=4)
                analysis_content += "\n"
            analysis_content += "Note: Analyze the entire call chain to understand what operations are performed.\n"
        
        # Add detailed reachability analysis
        if ctx.reachable_functions:
            total_reachable = len(ctx.reachable_functions)
            # Group reachable functions by file
            functions_by_file = {}
            for func in ctx.reachable_functions:
                if "::" in func:
                    file_path, func_name = func.rsplit("::", 1)
                    if file_path not in functions_by_file:
                        functions_by_file[file_path] = []
                    functions_by_file[file_path].append(func_name)
            
            if len(functions_by_file) > 1:  # More than just the current file
                analysis_content += f"\n**REACHABILITY ANALYSIS:**\n"
                analysis_content += f"Total reachable functions: {total_reachable} across {len(functions_by_file)} file(s)\n\n"
                for file_path, funcs in list(functions_by_file.items())[:5]:  # Show top 5 files
                    file_name = file_path.split('/')[-1] if '/' in file_path else file_path
                    analysis_content += f"  {file_name}: {', '.join(funcs[:10])}\n"
                    if len(funcs) > 10:
                        analysis_content += f"    ... and {len(funcs) - 10} more\n"
        
        # Add constants
        if ctx.constants:
            analysis_content += f"\n**CONSTANTS:**\n"
            for var, val in list(ctx.constants.items())[:10]:
                analysis_content += f"  {var} = {val}\n"
        
        # Add string literals (high-value security indicator)
        if ctx.string_literals:
            analysis_content += f"\n**STRING LITERALS ({len(ctx.string_literals)} total):**\n"
            for literal in ctx.string_literals[:15]:
                # Escape and truncate for safety
                safe_literal = literal.replace('\n', '\\n').replace('\r', '\\r')[:150]
                analysis_content += f"  \"{safe_literal}\"\n"
        
        # Add return expressions
        if ctx.return_expressions:
            analysis_content += f"\n**RETURN EXPRESSIONS:**\n"
            if ctx.return_type:
                analysis_content += f"Declared return type: {ctx.return_type}\n"
            for ret_expr in ctx.return_expressions:
                analysis_content += f"  return {ret_expr}\n"
        
        # Add exception handling details
        if ctx.exception_handlers:
            analysis_content += f"\n**EXCEPTION HANDLING:**\n"
            for handler in ctx.exception_handlers:
                analysis_content += f"  Line {handler['line']}: except {handler['exception_type']}"
                if handler['is_silent']:
                    analysis_content += " (⚠️  SILENT - just 'pass')\n"
                else:
                    analysis_content += "\n"
        
        # Add environment variable access
        if ctx.env_var_access:
            analysis_content += f"\n**ENVIRONMENT VARIABLE ACCESS:**\n"
            analysis_content += "⚠️  This function accesses environment variables:\n"
            for env_access in ctx.env_var_access:
                analysis_content += f"  {env_access}\n"
        
        # Add global variable writes
        if ctx.global_writes:
            analysis_content += f"\n**GLOBAL VARIABLE WRITES:**\n"
            analysis_content += "⚠️  This function modifies global state:\n"
            for gwrite in ctx.global_writes:
                analysis_content += f"  Line {gwrite['line']}: global {gwrite['variable']} = {gwrite['value']}\n"
        
        # Add attribute access (self.attr, obj.attr)
        if ctx.attribute_access:
            writes = [op for op in ctx.attribute_access if op['type'] == 'write']
            if writes:
                analysis_content += f"\n**ATTRIBUTE WRITES:**\n"
                for op in writes[:10]:
                    analysis_content += f"  Line {op['line']}: {op['object']}.{op['attribute']} = {op['value']}\n"
        
        # Add liveness analysis results
        if ctx.dead_variables:
            analysis_content += f"\n**DEAD CODE ANALYSIS:**\n"
            analysis_content += "Variables assigned but never used:\n"
            for var in ctx.dead_variables[:10]:
                analysis_content += f"  {var}\n"
        
        if ctx.unused_expressions:
            analysis_content += f"\n**UNUSED FUNCTION CALLS:**\n"
            analysis_content += "Functions called but results not captured or used:\n"
            for expr in ctx.unused_expressions[:10]:
                analysis_content += f"  {expr}\n"
        
        # Add scope and naming issues
        if ctx.scope_issues:
            analysis_content += f"\n**SCOPE/NAMING ISSUES:**\n"
            for issue in ctx.scope_issues[:10]:
                if issue['type'] == 'used_before_definition':
                    analysis_content += f"  Line {issue['line']}: Variable '{issue['variable']}' used before definition\n"
        
        # Add use-def chains for parameter-influenced variables
        if ctx.use_def_chains:
            param_influenced = {var: defs for var, defs in ctx.use_def_chains.items() 
                               if any('parameter:' in d for d in defs)}
            if param_influenced:
                analysis_content += f"\n**PARAMETER DATA FLOW:**\n"
                analysis_content += "Variables derived from parameters and their definitions:\n"
                for var, defs in list(param_influenced.items())[:10]:
                    analysis_content += f"  {var}: {', '.join(defs[:5])}\n"
        
        # Security validation: Check that the untrusted input doesn't contain our delimiter tags
        if start_tag in analysis_content or end_tag in analysis_content:
            self.logger.warning(
                f"Potential prompt injection detected in function {ctx.name}: Input contains delimiter tags"
            )
        
        # Wrap the untrusted content with randomized delimiters
        prompt = f"""{self._prompt_template}

{start_tag}
{analysis_content}
{end_tag}
"""
        
        return prompt.strip()
    
    def _parse_llm_response(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse LLM JSON response.
        
        Args:
            content: Raw LLM response
            
        Returns:
            Parsed dict or None
            
        Raises:
            ValueError: If the response cannot be parsed as valid JSON
        """
        if not content or not content.strip():
            raise ValueError("Empty response from LLM")
        
        try:
            # First, try to parse the entire response as JSON
            return json.loads(content.strip())
        except json.JSONDecodeError:
            pass
        
        try:
            # Try to extract JSON from the response by finding balanced braces
            content = content.strip()
            
            # Look for JSON object boundaries
            start_idx = content.find("{")
            if start_idx == -1:
                raise ValueError("No JSON object found in LLM response")
            
            # Find the matching closing brace
            brace_count = 0
            end_idx = -1
            
            for i in range(start_idx, len(content)):
                if content[i] == "{":
                    brace_count += 1
                elif content[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break
            
            if end_idx == -1:
                raise ValueError("No matching closing brace found in JSON")
            
            json_content = content[start_idx:end_idx]
            return json.loads(json_content)
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse LLM response as JSON: {e}")
            self.logger.error(f"Response content length: {len(content)} characters")
            raise ValueError(f"Invalid JSON in LLM response: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error parsing LLM response: {e}")
            self.logger.error(f"Response content length: {len(content)} characters")
            raise ValueError(f"Failed to parse LLM response: {e}")
