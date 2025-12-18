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
from typing import Any, Dict, List, Optional

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
    
    def __init__(
        self,
        max_operations: Optional[int] = None,
        max_calls: Optional[int] = None,
        max_assignments: Optional[int] = None,
        max_cross_file_calls: Optional[int] = None,
        max_reachable_files: Optional[int] = None,
        max_constants: Optional[int] = None,
        max_string_literals: Optional[int] = None,
        max_reaches_calls: Optional[int] = None
    ):
        """Initialize the alignment prompt builder.
        
        Args:
            max_operations: Maximum operations to show per parameter (default: from env or 10)
            max_calls: Maximum function calls to show (default: from env or 20)
            max_assignments: Maximum assignments to show (default: from env or 15)
            max_cross_file_calls: Maximum cross-file calls to show (default: from env or 10)
            max_reachable_files: Maximum reachable files to show (default: from env or 5)
            max_constants: Maximum constants to show (default: from env or 10)
            max_string_literals: Maximum string literals to show (default: from env or 15)
            max_reaches_calls: Maximum reaches calls to show (default: from env or 10)
        """
        self.logger = logging.getLogger(__name__)
        self._template = self._load_template()
        
        # Load limits from environment variables or use provided overrides
        self.MAX_OPERATIONS_PER_PARAM = max_operations or MCPScannerConstants.BEHAVIORAL_MAX_OPERATIONS_PER_PARAM
        self.MAX_FUNCTION_CALLS = max_calls or MCPScannerConstants.BEHAVIORAL_MAX_FUNCTION_CALLS
        self.MAX_ASSIGNMENTS = max_assignments or MCPScannerConstants.BEHAVIORAL_MAX_ASSIGNMENTS
        self.MAX_CROSS_FILE_CALLS = max_cross_file_calls or MCPScannerConstants.BEHAVIORAL_MAX_CROSS_FILE_CALLS
        self.MAX_REACHABLE_FILES = max_reachable_files or MCPScannerConstants.BEHAVIORAL_MAX_REACHABLE_FILES
        self.MAX_CONSTANTS = max_constants or MCPScannerConstants.BEHAVIORAL_MAX_CONSTANTS
        self.MAX_STRING_LITERALS = max_string_literals or MCPScannerConstants.BEHAVIORAL_MAX_STRING_LITERALS
        self.MAX_REACHES_CALLS = max_reaches_calls or MCPScannerConstants.BEHAVIORAL_MAX_REACHES_CALLS
    
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
        
        # Build the analysis content using list accumulation for efficiency
        content_parts = []
        
        # Entry point information
        content_parts.append(f"""**ENTRY POINT INFORMATION:**
- Function Name: {func_context.name}
- Decorator: {func_context.decorator_types[0] if func_context.decorator_types else 'unknown'}
- Line: {func_context.line_number}
- Docstring/Description: {docstring}



**FUNCTION SIGNATURE:**
- Parameters: {json.dumps(func_context.parameters, indent=2)}
- Return Type: {func_context.return_type or 'Not specified'}
""")
        
        # Add imports section
        if func_context.imports:
            import_parts = ["\n**IMPORTS:**\n"]
            import_parts.append("The following libraries and modules are imported:\n")
            for imp in func_context.imports:
                import_parts.append(f"  {imp}\n")
            import_parts.append("\n")
            content_parts.append(''.join(import_parts))
        
        content_parts.append("""
**DATAFLOW ANALYSIS:**
All parameters are treated as untrusted input (MCP entry points receive external data).

Parameter Flow Tracking:
""")
        
        # Add parameter flow tracking
        if func_context.parameter_flows:
            param_parts = ["\n**PARAMETER FLOW TRACKING:**\n"]
            for flow in func_context.parameter_flows:
                param_name = flow.get("parameter", "unknown")
                param_parts.append(f"\nParameter '{param_name}' flows through:\n")
                
                if flow.get("operations"):
                    param_parts.append(f"  Operations ({len(flow['operations'])} total):\n")
                    for op in flow["operations"][:self.MAX_OPERATIONS_PER_PARAM]:
                        op_type = op.get("type", "unknown")
                        line = op.get("line", 0)
                        if op_type == "assignment":
                            param_parts.append(f"    Line {line}: {op.get('target')} = {op.get('value')}\n")
                        elif op_type == "function_call":
                            param_parts.append(f"    Line {line}: {op.get('function')}({op.get('argument')})\n")
                        elif op_type == "return":
                            param_parts.append(f"    Line {line}: return {op.get('value')}\n")
                
                if flow.get("reaches_calls"):
                    param_parts.append(f"  Reaches function calls: {', '.join(flow['reaches_calls'][:self.MAX_REACHES_CALLS])}\n")
                
                if flow.get("reaches_external"):
                    param_parts.append(f"  ⚠️  REACHES EXTERNAL OPERATIONS (file/network/subprocess)\n")
                
                if flow.get("reaches_returns"):
                    param_parts.append(f"  Returns to caller\n")
            
            content_parts.append(''.join(param_parts))
        
        # Add variable dependencies
        if func_context.variable_dependencies:
            var_parts = ["\n**VARIABLE DEPENDENCIES:**\n"]
            for var, deps in func_context.variable_dependencies.items():
                var_parts.append(f"  {var} depends on: {', '.join(deps)}\n")
            content_parts.append(''.join(var_parts))
        
        # Add function calls
        if func_context.function_calls:
            call_parts = [f"\n**FUNCTION CALLS ({len(func_context.function_calls)} total):**\n"]
            for call in func_context.function_calls[:self.MAX_FUNCTION_CALLS]:
                try:
                    call_name = call.get('name', 'unknown')
                    call_args = call.get('args', [])
                    call_line = call.get('line', 0)
                    call_parts.append(f"  Line {call_line}: {call_name}({', '.join(str(a) for a in call_args)})\n")
                except Exception:
                    # Skip malformed call entries
                    continue
            content_parts.append(''.join(call_parts))
        
        # Add assignments
        if func_context.assignments:
            assign_parts = [f"\n**ASSIGNMENTS ({len(func_context.assignments)} total):**\n"]
            for assign in func_context.assignments[:self.MAX_ASSIGNMENTS]:
                try:
                    line = assign.get('line', 0)
                    var = assign.get('variable', 'unknown')
                    val = assign.get('value', 'unknown')
                    assign_parts.append(f"  Line {line}: {var} = {val}\n")
                except Exception:
                    continue
            content_parts.append(''.join(assign_parts))
        
        # Add control flow information
        if func_context.control_flow:
            content_parts.append(f"\n**CONTROL FLOW:**\n{json.dumps(func_context.control_flow, indent=2)}\n")
        
        # Add cross-file analysis with transitive call chains
        if func_context.cross_file_calls:
            cross_file_parts = [f"\n**CROSS-FILE CALL CHAINS ({len(func_context.cross_file_calls)} calls to other files):**\n"]
            cross_file_parts.append("⚠️  This function calls functions from other files. Full call chains shown:\n\n")
            for call in func_context.cross_file_calls[:self.MAX_CROSS_FILE_CALLS]:
                try:
                    # Handle both old format (function, file) and new format (from_function, to_function, etc.)
                    if 'to_function' in call:
                        cross_file_parts.append(f"  {call.get('from_function', 'unknown')} → {call.get('to_function', 'unknown')}\n")
                        cross_file_parts.append(f"    From: {call.get('from_file', 'unknown')}\n")
                        cross_file_parts.append(f"    To: {call.get('to_file', 'unknown')}\n")
                    else:
                        func_name = call.get('function', 'unknown')
                        file_name = call.get('file', 'unknown')
                        cross_file_parts.append(f"  {func_name}() in {file_name}\n")
                        # Show transitive calls
                        if call.get('call_chain'):
                            cross_file_parts.append(self._format_call_chain(call['call_chain'], indent=4))
                    cross_file_parts.append("\n")
                except Exception:
                    continue
            cross_file_parts.append("Note: Analyze the entire call chain to understand what operations are performed.\n")
            content_parts.append(''.join(cross_file_parts))
        
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
                reach_parts = [f"\n**REACHABILITY ANALYSIS:**\n"]
                reach_parts.append(f"Total reachable functions: {total_reachable} across {len(functions_by_file)} file(s)\n\n")
                for file_path, funcs in list(functions_by_file.items())[:self.MAX_REACHABLE_FILES]:
                    file_name = file_path.split('/')[-1] if '/' in file_path else file_path
                    reach_parts.append(f"  {file_name}: {', '.join(funcs[:10])}\n")
                    if len(funcs) > 10:
                        reach_parts.append(f"    ... and {len(funcs) - 10} more\n")
                content_parts.append(''.join(reach_parts))
        
        # Add constants
        if func_context.constants:
            const_parts = [f"\n**CONSTANTS:**\n"]
            for var, val in list(func_context.constants.items())[:self.MAX_CONSTANTS]:
                const_parts.append(f"  {var} = {val}\n")
            content_parts.append(''.join(const_parts))
        
        # Add string literals (high-value security indicator)
        if func_context.string_literals:
            lit_parts = [f"\n**STRING LITERALS ({len(func_context.string_literals)} total):**\n"]
            for literal in func_context.string_literals[:self.MAX_STRING_LITERALS]:
                # Escape and truncate for safety
                safe_literal = literal.replace('\n', '\\n').replace('\r', '\\r')[:150]
                lit_parts.append(f"  \"{safe_literal}\"\n")
            content_parts.append(''.join(lit_parts))
        
        # Add return expressions
        if func_context.return_expressions:
            ret_parts = [f"\n**RETURN EXPRESSIONS:**\n"]
            if func_context.return_type:
                ret_parts.append(f"Declared return type: {func_context.return_type}\n")
            for ret_expr in func_context.return_expressions:
                ret_parts.append(f"  return {ret_expr}\n")
            content_parts.append(''.join(ret_parts))
        
        # Add exception handling details
        if func_context.exception_handlers:
            exc_parts = [f"\n**EXCEPTION HANDLING:**\n"]
            for handler in func_context.exception_handlers:
                exc_parts.append(f"  Line {handler['line']}: except {handler['exception_type']}")
                if handler['is_silent']:
                    exc_parts.append(" (⚠️  SILENT - just 'pass')\n")
                else:
                    exc_parts.append("\n")
            content_parts.append(''.join(exc_parts))
        
        # Add environment variable access
        if func_context.env_var_access:
            env_parts = [f"\n**ENVIRONMENT VARIABLE ACCESS:**\n"]
            env_parts.append("⚠️  This function accesses environment variables:\n")
            for env_access in func_context.env_var_access:
                env_parts.append(f"  {env_access}\n")
            content_parts.append(''.join(env_parts))
        
        # Add global variable writes
        if func_context.global_writes:
            global_parts = [f"\n**GLOBAL VARIABLE WRITES:**\n"]
            global_parts.append("⚠️  This function modifies global state:\n")
            for gwrite in func_context.global_writes:
                global_parts.append(f"  Line {gwrite['line']}: global {gwrite['variable']} = {gwrite['value']}\n")
            content_parts.append(''.join(global_parts))
        
        # Add attribute access (self.attr, obj.attr)
        if func_context.attribute_access:
            writes = [op for op in func_context.attribute_access if op['type'] == 'write']
            if writes:
                attr_parts = [f"\n**ATTRIBUTE WRITES:**\n"]
                for op in writes[:10]:
                    attr_parts.append(f"  Line {op['line']}: {op['object']}.{op['attribute']} = {op['value']}\n")
                content_parts.append(''.join(attr_parts))
        
        # Join all content parts efficiently
        analysis_content = ''.join(content_parts)
        
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
