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

"""MCP Docstring Mismatch Analyzer.

This analyzer detects mismatches between MCP tool descriptions (docstrings) and 
actual code behavior using LLM analysis combined with complete dataflow, taint,
and constant propagation analysis from the supplychain engine.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from litellm import acompletion

from ...config.config import Config
from ...supplychain.context_extractor import CodeContextExtractor, FunctionContext
from .base import BaseAnalyzer, SecurityFinding


class MCPDocstringAnalyzer(BaseAnalyzer):
    """Analyzer for detecting mismatches between MCP tool descriptions and code behavior.
    
    This analyzer uses the complete supplychain analysis engine to:
    1. Identify MCP decorator usage (@mcp.tool, @mcp.prompt, @mcp.resource)
    2. Extract comprehensive code context (dataflow, taint, constants)
    3. Analyze actual code behavior using full AST + dataflow analysis
    4. Use LLM to detect semantic mismatches between description and implementation
    
    Example:
        >>> from mcpscanner import Config
        >>> from mcpscanner.analyzers import MCPDocstringAnalyzer
        >>> analyzer = MCPDocstringAnalyzer(config)
        >>> findings = await analyzer.analyze_file("/path/to/mcp_server.py")
    """

    def __init__(self, config: Config):
        """Initialize the analyzer with LLM configuration.
        
        Args:
            config: Configuration containing LLM credentials
        """
        super().__init__(name="MCPDocstring")
        self._config = config
        
        # LLM configuration
        self._model = config.llm_model
        self._api_key = config.llm_provider_api_key
        self._base_url = config.llm_base_url
        self._api_version = config.llm_api_version
        self._max_tokens = config.llm_max_tokens
        self._temperature = config.llm_temperature
        
        # Load prompt template
        self._prompt_template = self._load_prompt_template()
        
    async def analyze_file(self, file_path: str) -> List[SecurityFinding]:
        """Analyze a Python file for MCP docstring mismatches.
        
        Args:
            file_path: Path to Python file
            
        Returns:
            List of security findings
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read {file_path}: {e}")
            return []
        
        return await self.analyze(source_code, context={"file_path": file_path})

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze content for MCP docstring mismatches using complete dataflow analysis.
        
        Args:
            content: Python source code to analyze
            context: Optional context with file_path
            
        Returns:
            List of security findings
        """
        file_path = context.get("file_path", "unknown") if context else "unknown"
        findings = []
        
        try:
            # Use supplychain context extractor for complete analysis
            extractor = CodeContextExtractor(content, file_path)
            mcp_contexts = extractor.extract_mcp_function_contexts()
            
            if not mcp_contexts:
                self.logger.debug(f"No MCP functions found in {file_path}")
                return findings
            
            self.logger.info(f"Found {len(mcp_contexts)} MCP functions in {file_path}")
            
            # Analyze each MCP entry point
            for func_context in mcp_contexts:
                analysis = await self._analyze_mcp_entrypoint_with_llm(func_context)
                
                if not analysis or not analysis.get("mismatch_detected"):
                    continue
                
                # Create security finding
                severity = analysis.get("severity", "MEDIUM")
                
                # Use security_implications as the threat summary
                threat_summary = analysis.get("security_implications", f"Mismatch detected in {func_context.name}")
                
                finding = SecurityFinding(
                    severity=severity,
                    summary=threat_summary,
                    analyzer="MCPDocstring",
                    threat_category="DESCRIPTION_MISMATCH",
                    details={
                        "function_name": func_context.name,
                        "decorator_type": func_context.decorator_types[0] if func_context.decorator_types else "unknown",
                        "line_number": func_context.line_number,
                        "mismatch_type": analysis.get("mismatch_type"),
                        "description_claims": analysis.get("description_claims"),
                        "actual_behavior": analysis.get("actual_behavior"),
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

    def _load_prompt_template(self) -> str:
        """Load the description mismatch prompt template.
        
        Returns:
            Prompt template string
        """
        try:
            # Get the path to the prompts directory
            current_dir = Path(__file__).parent.parent.parent
            prompt_path = current_dir / "data" / "prompts" / "description_mismatch_prompt.md"
            
            with open(prompt_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            self.logger.warning(f"Failed to load prompt template: {e}, using fallback")
            return self._get_fallback_prompt()
    
    def _get_fallback_prompt(self) -> str:
        """Get fallback prompt if template file cannot be loaded.
        
        Returns:
            Fallback prompt string
        """
        return """Analyze this MCP entry point for mismatches between description and actual behavior.

Compare the docstring claims against the actual dataflow behavior. Only report clear mismatches with security implications.

Respond with JSON:
{
    "mismatch_detected": true/false,
    "severity": "HIGH/MEDIUM/LOW",
    "mismatch_type": "description_vs_behavior",
    "description_claims": "what the docstring says",
    "actual_behavior": "what the code does",
    "security_implications": "why this matters",
    "confidence": "HIGH/MEDIUM/LOW",
    "dataflow_evidence": "specific evidence"
}
"""
    
    def _create_comprehensive_analysis_prompt(self, ctx: FunctionContext) -> str:
        """Create comprehensive analysis prompt with full dataflow context.
        
        Args:
            ctx: Function context with complete analysis
            
        Returns:
            Formatted prompt string
        """
        docstring = ctx.docstring or "No docstring provided"
        
        # Build comprehensive context
        prompt = self._prompt_template + "\n\n"
        prompt += f"""**ENTRY POINT INFORMATION:**
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
            prompt += "\n**PARAMETER FLOW TRACKING:**\n"
            for flow in ctx.parameter_flows:
                param_name = flow.get("parameter", "unknown")
                prompt += f"\nParameter '{param_name}' flows through:\n"
                
                if flow.get("operations"):
                    prompt += f"  Operations ({len(flow['operations'])} total):\n"
                    for op in flow["operations"][:10]:  # Limit to first 10
                        op_type = op.get("type", "unknown")
                        line = op.get("line", 0)
                        if op_type == "assignment":
                            prompt += f"    Line {line}: {op.get('target')} = {op.get('value')}\n"
                        elif op_type == "function_call":
                            prompt += f"    Line {line}: {op.get('function')}({op.get('argument')})\n"
                        elif op_type == "return":
                            prompt += f"    Line {line}: return {op.get('value')}\n"
                
                if flow.get("reaches_calls"):
                    prompt += f"  Reaches function calls: {', '.join(flow['reaches_calls'][:10])}\n"
                
                if flow.get("reaches_external"):
                    prompt += f"  ⚠️  REACHES EXTERNAL OPERATIONS (file/network/subprocess)\n"
                
                if flow.get("reaches_returns"):
                    prompt += f"  Returns to caller\n"
        
        # Add variable dependencies
        if ctx.variable_dependencies:
            prompt += "\n**VARIABLE DEPENDENCIES:**\n"
            for var, deps in ctx.variable_dependencies.items():
                prompt += f"  {var} depends on: {', '.join(deps)}\n"
        
        # Add function calls
        prompt += f"\n**FUNCTION CALLS ({len(ctx.function_calls)} total):**\n"
        for call in ctx.function_calls[:20]:  # Limit to first 20
            prompt += f"  Line {call['line']}: {call['name']}({', '.join(call['args'])})\n"
        
        # Add assignments
        if ctx.assignments:
            prompt += f"\n**ASSIGNMENTS ({len(ctx.assignments)} total):**\n"
            for assign in ctx.assignments[:15]:  # Limit to first 15
                prompt += f"  Line {assign['line']}: {assign['variable']} = {assign['value']}\n"
        
        # Add control flow
        prompt += f"\n**CONTROL FLOW:**\n"
        prompt += f"- Has Conditionals: {ctx.control_flow.get('has_conditionals')}\n"
        prompt += f"- Has Loops: {ctx.control_flow.get('has_loops')}\n"
        prompt += f"- Has Exception Handling: {ctx.control_flow.get('has_exception_handling')}\n"
        prompt += f"- Cyclomatic Complexity: {ctx.dataflow_summary.get('complexity')}\n"
        
        # Add constants
        if ctx.constants:
            prompt += f"\n**CONSTANTS:**\n"
            for var, val in list(ctx.constants.items())[:10]:
                prompt += f"  {var} = {val}\n"
        
        
        return prompt

    def _parse_llm_response(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse LLM JSON response.
        
        Args:
            content: Raw LLM response
            
        Returns:
            Parsed dict or None
        """
        try:
            return json.loads(content.strip())
        except json.JSONDecodeError:
            start_idx = content.find("{")
            if start_idx == -1:
                return None
            
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
                return None
            
            try:
                return json.loads(content[start_idx:end_idx])
            except json.JSONDecodeError:
                return None
