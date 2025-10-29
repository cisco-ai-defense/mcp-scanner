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

"""Alignment Prompt Builder for Semantic Verification.

This module constructs comprehensive prompts for LLM-based semantic alignment
verification between MCP tool docstrings and their actual implementation behavior.

The prompt builder creates evidence-rich prompts that present:
- Docstring claims (what the tool says it does)
- Actual behavior evidence (what static analysis shows it does)
- Supporting dataflow, taint, and call graph evidence
"""

import json
import logging
import secrets
from pathlib import Path
from typing import Any, Dict, List

from .....config.constants import MCPScannerConstants
from ....static_analysis.context_extractor import FunctionContext


class AlignmentPromptBuilder:
    """Builds comprehensive prompts for semantic alignment verification.
    
    Constructs detailed prompts that provide LLMs with:
    - Function metadata and signatures
    - Parameter flow tracking evidence
    - Function call sequences
    - Cross-file call chains
    - Security indicators (file ops, network ops, etc.)
    - Control flow and data dependencies
    
    Uses randomized delimiters to prevent prompt injection attacks.
    """
    
    def __init__(self):
        """Initialize the alignment prompt builder."""
        self.logger = logging.getLogger(__name__)
        self._template = self._load_template()
    
    def build_prompt(self, func_context: FunctionContext) -> str:
        """Build comprehensive alignment verification prompt.
        
        Args:
            func_context: Complete function context with dataflow analysis
            
        Returns:
            Formatted prompt string with evidence
        """
        # Generate random delimiter tags to prevent prompt injection
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"
        
        docstring = func_context.docstring or "No docstring provided"
        
        # Build the analysis content (untrusted input)
        analysis_content = f"""**ENTRY POINT INFORMATION:**
- Function Name: {func_context.name}
- Decorator: {func_context.decorator_types[0] if func_context.decorator_types else 'unknown'}
- Line: {func_context.line_number}
- Docstring/Description: {docstring}



**FUNCTION SIGNATURE:**
- Parameters: {json.dumps(func_context.parameters, indent=2)}
- Return Type: {func_context.return_type or 'Not specified'}

**DATAFLOW ANALYSIS:**
All parameters are treated as untrusted input (MCP entry points receive external data).

Parameter Flow Tracking:
"""
        
        # Add parameter flow tracking
        if func_context.parameter_flows:
            analysis_content += "\n**PARAMETER FLOW TRACKING:**\n"
            for flow in func_context.parameter_flows:
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
        if func_context.variable_dependencies:
            analysis_content += "\n**VARIABLE DEPENDENCIES:**\n"
            for var, deps in func_context.variable_dependencies.items():
                analysis_content += f"  {var} depends on: {', '.join(deps)}\n"
        
        # Add function calls
        analysis_content += f"\n**FUNCTION CALLS ({len(func_context.function_calls)} total):**\n"
        for call in func_context.function_calls[:20]:  # Limit to first 20
            try:
                call_name = call.get('name', 'unknown')
                call_args = call.get('args', [])
                call_line = call.get('line', 0)
                analysis_content += f"  Line {call_line}: {call_name}({', '.join(str(a) for a in call_args)})\n"
            except Exception as e:
                # Skip malformed call entries
                continue
        
        # Add assignments
        if func_context.assignments:
            analysis_content += f"\n**ASSIGNMENTS ({len(func_context.assignments)} total):**\n"
            for assign in func_context.assignments[:15]:  # Limit to first 15
                try:
                    line = assign.get('line', 0)
                    var = assign.get('variable', 'unknown')
                    val = assign.get('value', 'unknown')
                    analysis_content += f"  Line {line}: {var} = {val}\n"
                except Exception:
                    continue
        
        # Add control flow information
        if func_context.control_flow:
            analysis_content += f"\n**CONTROL FLOW:**\n"
            analysis_content += f"{json.dumps(func_context.control_flow, indent=2)}\n"
        
        # Add cross-file analysis with transitive call chains
        if func_context.cross_file_calls:
            analysis_content += f"\n**CROSS-FILE CALL CHAINS ({len(func_context.cross_file_calls)} calls to other files):**\n"
            analysis_content += "⚠️  This function calls functions from other files. Full call chains shown:\n\n"
            for call in func_context.cross_file_calls[:10]:
                try:
                    # Handle both old format (function, file) and new format (from_function, to_function, etc.)
                    if 'to_function' in call:
                        analysis_content += f"  {call.get('from_function', 'unknown')} → {call.get('to_function', 'unknown')}\n"
                        analysis_content += f"    From: {call.get('from_file', 'unknown')}\n"
                        analysis_content += f"    To: {call.get('to_file', 'unknown')}\n"
                    else:
                        func_name = call.get('function', 'unknown')
                        file_name = call.get('file', 'unknown')
                        analysis_content += f"  {func_name}() in {file_name}\n"
                        # Show transitive calls
                        if call.get('call_chain'):
                            analysis_content += self._format_call_chain(call['call_chain'], indent=4)
                    analysis_content += "\n"
                except Exception:
                    continue
            analysis_content += "Note: Analyze the entire call chain to understand what operations are performed.\n"
        
        # Add detailed reachability analysis
        if func_context.reachable_functions:
            total_reachable = len(func_context.reachable_functions)
            # Group reachable functions by file
            functions_by_file = {}
            for func in func_context.reachable_functions:
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
        if func_context.constants:
            analysis_content += f"\n**CONSTANTS:**\n"
            for var, val in list(func_context.constants.items())[:10]:
                analysis_content += f"  {var} = {val}\n"
        
        # Add string literals (high-value security indicator)
        if func_context.string_literals:
            analysis_content += f"\n**STRING LITERALS ({len(func_context.string_literals)} total):**\n"
            for literal in func_context.string_literals[:15]:
                # Escape and truncate for safety
                safe_literal = literal.replace('\n', '\\n').replace('\r', '\\r')[:150]
                analysis_content += f"  \"{safe_literal}\"\n"
        
        # Add return expressions
        if func_context.return_expressions:
            analysis_content += f"\n**RETURN EXPRESSIONS:**\n"
            if func_context.return_type:
                analysis_content += f"Declared return type: {func_context.return_type}\n"
            for ret_expr in func_context.return_expressions:
                analysis_content += f"  return {ret_expr}\n"
        
        # Add exception handling details
        if func_context.exception_handlers:
            analysis_content += f"\n**EXCEPTION HANDLING:**\n"
            for handler in func_context.exception_handlers:
                analysis_content += f"  Line {handler['line']}: except {handler['exception_type']}"
                if handler['is_silent']:
                    analysis_content += " (⚠️  SILENT - just 'pass')\n"
                else:
                    analysis_content += "\n"
        
        # Add environment variable access
        if func_context.env_var_access:
            analysis_content += f"\n**ENVIRONMENT VARIABLE ACCESS:**\n"
            analysis_content += "⚠️  This function accesses environment variables:\n"
            for env_access in func_context.env_var_access:
                analysis_content += f"  {env_access}\n"
        
        # Add global variable writes
        if func_context.global_writes:
            analysis_content += f"\n**GLOBAL VARIABLE WRITES:**\n"
            analysis_content += "⚠️  This function modifies global state:\n"
            for gwrite in func_context.global_writes:
                analysis_content += f"  Line {gwrite['line']}: global {gwrite['variable']} = {gwrite['value']}\n"
        
        # Add attribute access (self.attr, obj.attr)
        if func_context.attribute_access:
            writes = [op for op in func_context.attribute_access if op['type'] == 'write']
            if writes:
                analysis_content += f"\n**ATTRIBUTE WRITES:**\n"
                for op in writes[:10]:
                    analysis_content += f"  Line {op['line']}: {op['object']}.{op['attribute']} = {op['value']}\n"
        
        # Security validation: Check that the untrusted input doesn't contain our delimiter tags
        if start_tag in analysis_content or end_tag in analysis_content:
            self.logger.warning(
                f"Potential prompt injection detected in function {func_context.name}: Input contains delimiter tags"
            )
        
        # Wrap the untrusted content with randomized delimiters
        prompt = f"""{self._template}

{start_tag}
{analysis_content}
{end_tag}
"""
        
        return prompt.strip()
    
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
    
    def _load_template(self) -> str:
        """Load the alignment verification prompt template.
        
        Returns:
            Prompt template string
            
        Raises:
            FileNotFoundError: If the prompt file cannot be found
            IOError: If the prompt file cannot be read
        """
        try:
            prompt_file = MCPScannerConstants.get_prompts_path() / "code_alignment_threat_analysis_prompt.md"
            
            if not prompt_file.is_file():
                raise FileNotFoundError("Prompt file not found: code_alignment_threat_analysis_prompt.md")
            
            return prompt_file.read_text(encoding="utf-8")
            
        except FileNotFoundError:
            self.logger.error("Prompt file not found: code_alignment_threat_analysis_prompt.md")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load prompt code_alignment_threat_analysis_prompt.md: {e}")
            raise IOError(f"Could not load prompt code_alignment_threat_analysis_prompt.md: {e}")
