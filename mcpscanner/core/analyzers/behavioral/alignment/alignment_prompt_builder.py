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
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

from .....config.constants import MCPScannerConstants
from ....static_analysis.context_extractor import FunctionContext

_GRAPH_EVIDENCE_HEADER = (
    "\n**CODE GRAPH EVIDENCE (deterministic static analysis):**\n"
)
_CLASSIC_DATAFLOW_HEADER = (
    "\n**CLASSIC DATAFLOW (reaching-defs / liveness / available-exprs):**\n"
)
_SINK_HINTS_HEADER = (
    "\n**CODE GRAPH SINK HINTS (deterministic, verify against docstring):**\n"
)
_PRESERVED_SECTION_HEADERS = (
    _GRAPH_EVIDENCE_HEADER,
    _CLASSIC_DATAFLOW_HEADER,
    _SINK_HINTS_HEADER,
)
_SECTION_HEADER_RE = re.compile(r"\n\*\*[^*\n][^\n]*\n")


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    sorted_ranges = sorted(ranges)
    merged = [sorted_ranges[0]]
    for start, end in sorted_ranges[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _split_preserved_sections(analysis_content: str) -> tuple[str, str]:
    """Separate deterministic graph blocks so truncation cannot drop them."""
    if not any(header in analysis_content for header in _PRESERVED_SECTION_HEADERS):
        return analysis_content, ""

    ranges: list[tuple[int, int]] = []
    preserved_chunks: list[str] = []
    for header in _PRESERVED_SECTION_HEADERS:
        start = 0
        while True:
            pos = analysis_content.find(header, start)
            if pos == -1:
                break
            body_start = pos + len(header)
            match = _SECTION_HEADER_RE.search(analysis_content, body_start)
            end = match.start() if match else len(analysis_content)
            ranges.append((pos, end))
            preserved_chunks.append(analysis_content[pos:end])
            start = pos + 1

    if not ranges:
        return analysis_content, ""

    main_parts: list[str] = []
    cursor = 0
    for start, end in _merge_ranges(ranges):
        main_parts.append(analysis_content[cursor:start])
        cursor = end
    main_parts.append(analysis_content[cursor:])
    return "".join(main_parts), "".join(preserved_chunks)


def _cap_preserved_sections(preserved: str, max_preserved: int) -> str:
    """Shrink preserved graph blocks; drop classic dataflow before sink hints."""
    if len(preserved) <= max_preserved:
        return preserved

    chunks: list[tuple[int, str]] = []
    for header in reversed(_PRESERVED_SECTION_HEADERS):
        while header in preserved:
            pos = preserved.find(header)
            body_start = pos + len(header)
            match = _SECTION_HEADER_RE.search(preserved, body_start)
            end = match.start() if match else len(preserved)
            chunk = preserved[pos:end]
            priority = (
                0
                if header == _SINK_HINTS_HEADER
                else 1
                if header == _GRAPH_EVIDENCE_HEADER
                else 2
            )
            chunks.append((priority, chunk))
            preserved = preserved[:pos] + preserved[end:]

    chunks.sort(key=lambda item: item[0])
    kept: list[str] = []
    used = 0
    for _, chunk in chunks:
        if used + len(chunk) <= max_preserved:
            kept.append(chunk)
            used += len(chunk)
            continue
        remaining = max_preserved - used
        header_line = chunk.split("\n", 1)[0] + "\n"
        if remaining <= len(header_line) + 20:
            continue
        kept.append(chunk[:remaining] + "\n... (graph section truncated)\n")
        used = max_preserved
        break

    if not kept:
        joined = "".join(chunk for _, chunk in chunks)
        return joined[:max_preserved] + "\n... (graph evidence truncated)\n"
    return "".join(kept)


def _truncate_analysis_preserving_graph(
    main: str,
    preserved: str,
    max_analysis: int,
) -> str:
    """Truncate non-graph analysis text; graph blocks are appended intact."""
    preserved = preserved or ""
    if len(main) + len(preserved) <= max_analysis:
        return main + preserved

    suffix_len = len(_ANALYSIS_TRUNCATION_SUFFIX)
    preserved_budget = min(len(preserved), max_analysis)
    preserved_kept = _cap_preserved_sections(preserved, preserved_budget)
    main_budget = max(0, max_analysis - len(preserved_kept) - suffix_len)
    if len(main) > main_budget:
        if main_budget <= suffix_len:
            main = _ANALYSIS_TRUNCATION_SUFFIX.strip()
        else:
            main = main[: main_budget - suffix_len] + _ANALYSIS_TRUNCATION_SUFFIX
    return main + preserved_kept


# Worst-case suffixes reserved when budgeting total prompt size.
_ANALYSIS_TRUNCATION_SUFFIX = (
    "\n\n... (analysis evidence truncated to fit model context budget)\n"
)
_TEMPLATE_TRUNCATION_SUFFIX = (
    "\n\n... (alignment instructions truncated to fit model context budget)\n"
)
_MIN_ANALYSIS_CHARS = 500
_MAX_PRESERVED_TOTAL_CHARS = 12_000
_RESPONSE_FORMAT_MARKER = "## Required Output Format"
# Newlines joining template, prefix, delimiter tags, and analysis body.
_PROMPT_FRAME_CHARS = 5


def _cap_prompt_preserving_end_tag(
    prompt: str, *, max_total: int, end_tag: str
) -> str:
    """Hard-cap prompt length while keeping the untrusted-input closing fence."""
    if len(prompt) <= max_total:
        return prompt
    trailer = f"\n{end_tag}\n"
    if len(trailer) >= max_total:
        if end_tag and max_total > 0:
            return end_tag[-max_total:]
        return prompt[:max_total]
    body_budget = max_total - len(trailer)
    return prompt[:body_budget].rstrip() + trailer


def _split_template(template: str) -> tuple[str, str]:
    """Split truncatable guidance from the pinned response-schema tail."""
    if _RESPONSE_FORMAT_MARKER not in template:
        return template, ""
    guidance, pinned = template.split(_RESPONSE_FORMAT_MARKER, 1)
    return guidance.rstrip(), _RESPONSE_FORMAT_MARKER + pinned


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
        max_reaches_calls: Optional[int] = None,
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
        full_template = self._load_template()
        self._template_guidance, self._template_pinned = _split_template(full_template)
        self._template = self._template_guidance + self._template_pinned

        # Load limits from environment variables or use provided overrides
        self.MAX_OPERATIONS_PER_PARAM = (
            max_operations or MCPScannerConstants.BEHAVIORAL_MAX_OPERATIONS_PER_PARAM
        )
        self.MAX_FUNCTION_CALLS = (
            max_calls or MCPScannerConstants.BEHAVIORAL_MAX_FUNCTION_CALLS
        )
        self.MAX_ASSIGNMENTS = (
            max_assignments or MCPScannerConstants.BEHAVIORAL_MAX_ASSIGNMENTS
        )
        self.MAX_CROSS_FILE_CALLS = (
            max_cross_file_calls or MCPScannerConstants.BEHAVIORAL_MAX_CROSS_FILE_CALLS
        )
        self.MAX_REACHABLE_FILES = (
            max_reachable_files or MCPScannerConstants.BEHAVIORAL_MAX_REACHABLE_FILES
        )
        self.MAX_CONSTANTS = (
            max_constants or MCPScannerConstants.BEHAVIORAL_MAX_CONSTANTS
        )
        self.MAX_STRING_LITERALS = (
            max_string_literals or MCPScannerConstants.BEHAVIORAL_MAX_STRING_LITERALS
        )
        self.MAX_REACHES_CALLS = (
            max_reaches_calls or MCPScannerConstants.BEHAVIORAL_MAX_REACHES_CALLS
        )

    @staticmethod
    def _format_graph_evidence_section(func_context: FunctionContext) -> str:
        summary = func_context.dataflow_summary or {}
        parts: list[str] = []

        graph_evidence = summary.get("code_graph_evidence")
        if graph_evidence:
            parts.append(
                "\n**CODE GRAPH EVIDENCE (deterministic static analysis):**\n"
                f"{graph_evidence}\n"
            )

        classic = summary.get("classic_dataflow")
        if classic:
            parts.append(
                "\n**CLASSIC DATAFLOW (reaching-defs / liveness / available-exprs):**\n"
                f"{json.dumps(classic, indent=2)}\n"
            )

        sink_hints = summary.get("code_graph_sink_hints")
        if sink_hints:
            parts.append(
                "\n**CODE GRAPH SINK HINTS (deterministic, verify against docstring):**\n"
                f"{json.dumps(sink_hints, indent=2)}\n"
            )

        return "".join(parts)

    def build_analysis_content(self, func_context: FunctionContext) -> str:
        """Build deterministic alignment evidence (no random delimiters)."""
        docstring = func_context.docstring or "No docstring provided"

        # Build the analysis content using list accumulation for efficiency
        content_parts = []

        # Entry point information
        content_parts.append(
            f"""**ENTRY POINT INFORMATION:**
- Function Name: {func_context.name}
- Decorator: {func_context.decorator_types[0] if func_context.decorator_types else 'unknown'}
- Line: {func_context.line_number}
- Docstring/Description: {docstring}



**FUNCTION SIGNATURE:**
- Parameters: {json.dumps(func_context.parameters, indent=2)}
- Return Type: {func_context.return_type or 'Not specified'}
"""
        )

        # Add imports section
        if func_context.imports:
            import_parts = ["\n**IMPORTS:**\n"]
            import_parts.append("The following libraries and modules are imported:\n")
            for imp in func_context.imports:
                import_parts.append(f"  {imp}\n")
            import_parts.append("\n")
            content_parts.append("".join(import_parts))

        content_parts.append(
            """
**DATAFLOW ANALYSIS:**
All parameters are treated as untrusted input (MCP entry points receive external data).

Parameter Flow Tracking:
"""
        )

        # Add parameter flow tracking
        if func_context.parameter_flows:
            param_parts = ["\n**PARAMETER FLOW TRACKING:**\n"]
            for flow in func_context.parameter_flows:
                param_name = flow.get("parameter", "unknown")
                param_parts.append(f"\nParameter '{param_name}' flows through:\n")

                if flow.get("operations"):
                    param_parts.append(
                        f"  Operations ({len(flow['operations'])} total):\n"
                    )
                    for op in flow["operations"][: self.MAX_OPERATIONS_PER_PARAM]:
                        op_type = op.get("type", "unknown")
                        line = op.get("line", 0)
                        if op_type == "assignment":
                            param_parts.append(
                                f"    Line {line}: {op.get('target')} = {op.get('value')}\n"
                            )
                        elif op_type == "function_call":
                            param_parts.append(
                                f"    Line {line}: {op.get('function')}({op.get('argument')})\n"
                            )
                        elif op_type == "return":
                            param_parts.append(
                                f"    Line {line}: return {op.get('value')}\n"
                            )

                if flow.get("reaches_calls"):
                    param_parts.append(
                        f"  Reaches function calls: {', '.join(flow['reaches_calls'][:self.MAX_REACHES_CALLS])}\n"
                    )

                if flow.get("reaches_external"):
                    param_parts.append(
                        f"  ⚠️  REACHES EXTERNAL OPERATIONS (file/network/subprocess)\n"
                    )

                if flow.get("reaches_returns"):
                    param_parts.append(f"  Returns to caller\n")

            content_parts.append("".join(param_parts))

        # Add variable dependencies
        if func_context.variable_dependencies:
            var_parts = ["\n**VARIABLE DEPENDENCIES:**\n"]
            for var, deps in func_context.variable_dependencies.items():
                var_parts.append(f"  {var} depends on: {', '.join(deps)}\n")
            content_parts.append("".join(var_parts))

        # Add function calls
        if func_context.function_calls:
            call_parts = [
                f"\n**FUNCTION CALLS ({len(func_context.function_calls)} total):**\n"
            ]
            for call in func_context.function_calls[: self.MAX_FUNCTION_CALLS]:
                try:
                    call_name = call.get("name", "unknown")
                    call_args = call.get("args", [])
                    call_line = call.get("line", 0)
                    call_parts.append(
                        f"  Line {call_line}: {call_name}({', '.join(str(a) for a in call_args)})\n"
                    )
                except Exception:
                    # Skip malformed call entries
                    continue
            content_parts.append("".join(call_parts))

        # Add assignments
        if func_context.assignments:
            assign_parts = [
                f"\n**ASSIGNMENTS ({len(func_context.assignments)} total):**\n"
            ]
            for assign in func_context.assignments[: self.MAX_ASSIGNMENTS]:
                try:
                    line = assign.get("line", 0)
                    var = assign.get("variable", "unknown")
                    val = assign.get("value", "unknown")
                    assign_parts.append(f"  Line {line}: {var} = {val}\n")
                except Exception:
                    continue
            content_parts.append("".join(assign_parts))

        # Add control flow information
        if func_context.control_flow:
            content_parts.append(
                f"\n**CONTROL FLOW:**\n{json.dumps(func_context.control_flow, indent=2)}\n"
            )

        # Add cross-file analysis with transitive call chains
        if func_context.cross_file_calls:
            cross_file_parts = [
                f"\n**CROSS-FILE CALL CHAINS ({len(func_context.cross_file_calls)} calls to other files):**\n"
            ]
            cross_file_parts.append(
                "⚠️  This function calls functions from other files. Full call chains shown:\n\n"
            )
            for call in func_context.cross_file_calls[: self.MAX_CROSS_FILE_CALLS]:
                try:
                    # Handle both old format (function, file) and new format (from_function, to_function, etc.)
                    if "to_function" in call:
                        cross_file_parts.append(
                            f"  {call.get('from_function', 'unknown')} → {call.get('to_function', 'unknown')}\n"
                        )
                        cross_file_parts.append(
                            f"    From: {call.get('from_file', 'unknown')}\n"
                        )
                        cross_file_parts.append(
                            f"    To: {call.get('to_file', 'unknown')}\n"
                        )
                    else:
                        func_name = call.get("function", "unknown")
                        file_name = call.get("file", "unknown")
                        cross_file_parts.append(f"  {func_name}() in {file_name}\n")
                        # Show transitive calls
                        if call.get("call_chain"):
                            cross_file_parts.append(
                                self._format_call_chain(call["call_chain"], indent=4)
                            )
                    cross_file_parts.append("\n")
                except Exception:
                    continue
            cross_file_parts.append(
                "Note: Analyze the entire call chain to understand what operations are performed.\n"
            )
            content_parts.append("".join(cross_file_parts))

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
                reach_parts.append(
                    f"Total reachable functions: {total_reachable} across {len(functions_by_file)} file(s)\n\n"
                )
                for file_path, funcs in list(functions_by_file.items())[
                    : self.MAX_REACHABLE_FILES
                ]:
                    file_name = (
                        file_path.split("/")[-1] if "/" in file_path else file_path
                    )
                    reach_parts.append(f"  {file_name}: {', '.join(funcs[:10])}\n")
                    if len(funcs) > 10:
                        reach_parts.append(f"    ... and {len(funcs) - 10} more\n")
                content_parts.append("".join(reach_parts))

        # Add constants
        if func_context.constants:
            const_parts = [f"\n**CONSTANTS:**\n"]
            for var, val in list(func_context.constants.items())[: self.MAX_CONSTANTS]:
                const_parts.append(f"  {var} = {val}\n")
            content_parts.append("".join(const_parts))

        # Add string literals (high-value security indicator)
        if func_context.string_literals:
            lit_parts = [
                f"\n**STRING LITERALS ({len(func_context.string_literals)} total):**\n"
            ]
            for literal in func_context.string_literals[: self.MAX_STRING_LITERALS]:
                # Escape and truncate for safety
                safe_literal = literal.replace("\n", "\\n").replace("\r", "\\r")[:150]
                lit_parts.append(f'  "{safe_literal}"\n')
            content_parts.append("".join(lit_parts))

        # Add return expressions
        if func_context.return_expressions:
            ret_parts = [f"\n**RETURN EXPRESSIONS:**\n"]
            if func_context.return_type:
                ret_parts.append(f"Declared return type: {func_context.return_type}\n")
            for ret_expr in func_context.return_expressions:
                ret_parts.append(f"  return {ret_expr}\n")
            content_parts.append("".join(ret_parts))

        # Add exception handling details
        if func_context.exception_handlers:
            exc_parts = [f"\n**EXCEPTION HANDLING:**\n"]
            for handler in func_context.exception_handlers:
                exc_type = handler.get('exception_type', 'Exception')
                line = handler.get('line', '?')
                exc_parts.append(
                    f"  Line {line}: except {exc_type}"
                )
                if handler.get("is_silent", False):
                    exc_parts.append(" (⚠️  SILENT - just 'pass')\n")
                else:
                    exc_parts.append("\n")
            content_parts.append("".join(exc_parts))

        # Add environment variable access
        if func_context.env_var_access:
            env_parts = [f"\n**ENVIRONMENT VARIABLE ACCESS:**\n"]
            env_parts.append("⚠️  This function accesses environment variables:\n")
            for env_access in func_context.env_var_access:
                env_parts.append(f"  {env_access}\n")
            content_parts.append("".join(env_parts))

        # Add global variable writes
        if func_context.global_writes:
            global_parts = [f"\n**GLOBAL VARIABLE WRITES:**\n"]
            global_parts.append("⚠️  This function modifies global state:\n")
            for gwrite in func_context.global_writes:
                global_parts.append(
                    f"  Line {gwrite['line']}: global {gwrite['variable']} = {gwrite['value']}\n"
                )
            content_parts.append("".join(global_parts))

        # Add attribute access (self.attr, obj.attr)
        if func_context.attribute_access:
            writes = [
                op for op in func_context.attribute_access if op.get("type") == "write"
            ]
            if writes:
                attr_parts = [f"\n**ATTRIBUTE WRITES:**\n"]
                for op in writes[:10]:
                    line = op.get('line', '?')
                    obj = op.get('object', '?')
                    attr = op.get('attribute', '?')
                    val = op.get('value', '?')
                    attr_parts.append(
                        f"  Line {line}: {obj}.{attr} = {val}\n"
                    )
                content_parts.append("".join(attr_parts))

        graph_section = self._format_graph_evidence_section(func_context)
        if graph_section:
            content_parts.append(graph_section)

        return "".join(content_parts)

    def build_prompt(self, func_context: FunctionContext) -> str:
        """Build comprehensive alignment verification prompt.

        Args:
            func_context: Complete function context with dataflow analysis

        Returns:
            Formatted prompt string with evidence
        """
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"

        analysis_content = self.build_analysis_content(func_context)

        # Security validation: Check that the untrusted input doesn't contain our delimiter tags
        if start_tag in analysis_content or end_tag in analysis_content:
            self.logger.warning(
                "prompt_injection_detected function=%s detail=%s",
                func_context.name,
                "untrusted_input_contains_delimiter_tag",
            )

        return self._assemble_prompt(
            template=self._template,
            analysis_content=analysis_content,
            start_tag=start_tag,
            end_tag=end_tag,
            log_label=f"function={func_context.name}",
        )

    def build_batch_analysis_content(
        self, func_contexts: List[FunctionContext]
    ) -> str:
        """Build deterministic batch body (no random delimiters).

        Reused across batch parse retries; only delimiter tags change.
        """
        all_content = []
        all_content.append(
            f"Analyze the following {len(func_contexts)} functions for security threats.\n"
        )
        all_content.append("For EACH function, provide a separate JSON analysis.\n")
        all_content.append(
            'Return a JSON object with a "results" array containing one object per function in the same order.\n\n'
        )

        for idx, func_context in enumerate(func_contexts):
            docstring = func_context.docstring or "No docstring provided"

            all_content.append(
                f"=== FUNCTION {idx + 1} of {len(func_contexts)} ===\n"
            )
            all_content.append(f"**Function Name:** {func_context.name}\n")
            all_content.append(f"**Line:** {func_context.line_number}\n")
            all_content.append(
                f"**Decorator:** {func_context.decorator_types[0] if func_context.decorator_types else 'unknown'}\n"
            )
            all_content.append(f"**Docstring:** {docstring}\n")
            all_content.append(
                f"**Parameters:** {json.dumps(func_context.parameters)}\n"
            )
            all_content.append(
                f"**Return Type:** {func_context.return_type or 'Not specified'}\n"
            )

            if func_context.function_calls:
                calls = [c.get("name", "?") for c in func_context.function_calls[:10]]
                all_content.append(f"**Function Calls:** {', '.join(calls)}\n")

            security_flags = []
            if getattr(func_context, "has_file_operations", False):
                security_flags.append("FILE_OPS")
            if getattr(func_context, "has_network_operations", False):
                security_flags.append("NETWORK_OPS")
            if getattr(func_context, "has_subprocess_calls", False):
                security_flags.append("SUBPROCESS")
            if getattr(func_context, "has_eval_exec", False):
                security_flags.append("EVAL/EXEC")
            if security_flags:
                all_content.append(
                    f"**Security Flags:** {', '.join(security_flags)}\n"
                )

            source = getattr(func_context, "source", "")
            if source:
                if len(source) > 2000:
                    source = source[:2000] + "\n... (truncated)"
                all_content.append(f"**Source Code:**\n```\n{source}\n```\n")

            graph_section = self._format_graph_evidence_section(func_context)
            if graph_section:
                all_content.append(graph_section)

            all_content.append("\n")

        return "".join(all_content)

    def wrap_batch_prompt(
        self,
        func_contexts: List[FunctionContext],
        analysis_content: str,
    ) -> str:
        """Wrap pre-built batch content with fresh anti-injection delimiters."""
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"

        batch_instructions = """
IMPORTANT: You are analyzing MULTIPLE functions. Return a JSON OBJECT with a "results" array containing one analysis object per function.

Example response format for 3 functions:
```json
{
  "results": [
    {"function_index": 0, "function_name": "func1", "mismatch_detected": false},
    {"function_index": 1, "function_name": "func2", "mismatch_detected": true, "threat_name": "DATA EXFILTRATION", "severity": "HIGH", "description_claims": "...", "actual_behavior": "...", "security_implications": "..."},
    {"function_index": 2, "function_name": "func3", "mismatch_detected": false}
  ]
}
```

For each function with mismatch_detected=true, include all required fields (threat_name, severity, description_claims, actual_behavior, security_implications).
For functions with no issues, just include function_index, function_name, and mismatch_detected=false.

"""
        return self._assemble_prompt(
            template=self._template,
            prefix=batch_instructions,
            analysis_content=analysis_content,
            start_tag=start_tag,
            end_tag=end_tag,
            log_label=f"batch_functions={len(func_contexts)}",
            relocate_preserved=False,
        )

    def build_batch_prompt(self, func_contexts: List[FunctionContext]) -> str:
        """Build a batched prompt for analyzing multiple functions in one LLM call.

        Args:
            func_contexts: List of function contexts to analyze

        Returns:
            Formatted prompt string with all functions
        """
        analysis_content = self.build_batch_analysis_content(func_contexts)
        return self.wrap_batch_prompt(func_contexts, analysis_content)

    def _assemble_prompt(
        self,
        *,
        template: str,
        analysis_content: str,
        start_tag: str,
        end_tag: str,
        log_label: str,
        prefix: str = "",
        relocate_preserved: bool = True,
    ) -> str:
        """Build the final prompt and enforce the alignment context budget."""
        original_analysis_content = analysis_content
        max_total = MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS
        frame_overhead = (
            len(prefix) + len(start_tag) + len(end_tag) + _PROMPT_FRAME_CHARS
        )
        available = max(0, max_total - frame_overhead)

        guidance, pinned = _split_template(template)
        pinned_len = len(pinned)

        main = ""
        preserved = ""
        if relocate_preserved:
            main, preserved = _split_preserved_sections(analysis_content)
            preserved_budget = min(
                _MAX_PRESERVED_TOTAL_CHARS,
                max(len(preserved), available // 3),
            )
            preserved = _cap_preserved_sections(preserved, preserved_budget)
        else:
            preserved_budget = 0

        reserved_analysis = (
            pinned_len
            + len(preserved)
            + _MIN_ANALYSIS_CHARS
            + len(_ANALYSIS_TRUNCATION_SUFFIX)
        )
        max_guidance_len = max(0, available - reserved_analysis)

        guidance_used = guidance
        if len(guidance) > max_guidance_len:
            allow = max(0, max_guidance_len - len(_TEMPLATE_TRUNCATION_SUFFIX))
            guidance_used = guidance[:allow] + _TEMPLATE_TRUNCATION_SUFFIX
            self.logger.warning(
                "prompt template truncated label=%s template_length=%d "
                "max_guidance=%d pinned=%d budget=%d preserved_reserved=%d",
                log_label,
                len(guidance),
                max_guidance_len,
                pinned_len,
                max_total,
                len(preserved),
            )

        template_used = guidance_used + pinned
        max_analysis = max(
            len(preserved),
            available - len(template_used) - len(_ANALYSIS_TRUNCATION_SUFFIX),
        )
        original_analysis_len = len(analysis_content)
        if relocate_preserved:
            if len(original_analysis_content) <= max_analysis:
                analysis_content = original_analysis_content
            elif len(main) + len(preserved) > max_analysis:
                self.logger.warning(
                    "prompt truncated label=%s analysis_length=%d max_analysis=%d "
                    "budget=%d preserved=%d pinned=%d",
                    log_label,
                    original_analysis_len,
                    max_analysis,
                    max_total,
                    len(preserved),
                    pinned_len,
                )
                analysis_content = _truncate_analysis_preserving_graph(
                    main, preserved, max_analysis
                )
            else:
                analysis_content = main + preserved
        elif len(analysis_content) > max_analysis:
            self.logger.warning(
                "prompt truncated label=%s analysis_length=%d max_analysis=%d "
                "budget=%d preserved=%d pinned=%d",
                log_label,
                original_analysis_len,
                max_analysis,
                max_total,
                len(preserved),
                pinned_len,
            )
            suffix_len = len(_ANALYSIS_TRUNCATION_SUFFIX)
            if max_analysis <= suffix_len:
                analysis_content = _ANALYSIS_TRUNCATION_SUFFIX.strip()
            else:
                analysis_content = (
                    analysis_content[: max_analysis - suffix_len]
                    + _ANALYSIS_TRUNCATION_SUFFIX
                )

        def _build(template_body: str, body: str) -> str:
            return (
                f"""{template_body}

{prefix}{start_tag}
{body}
{end_tag}
"""
            ).strip()

        prompt = _build(template_used, analysis_content)
        previous_len: Optional[int] = None
        while len(prompt) > max_total:
            guidance_body = guidance_used
            if guidance_used.endswith(_TEMPLATE_TRUNCATION_SUFFIX):
                guidance_body = guidance_used[: -len(_TEMPLATE_TRUNCATION_SUFFIX)]

            if len(guidance_body) > 0 and previous_len != len(prompt):
                previous_len = len(prompt)
                new_len = max(
                    0, len(guidance_body) - max(256, len(guidance_body) // 10)
                )
                if new_len < len(guidance):
                    guidance_used = guidance[:new_len] + _TEMPLATE_TRUNCATION_SUFFIX
                else:
                    guidance_used = guidance_body[:new_len]
                template_used = guidance_used + pinned
                max_analysis = max(
                    len(preserved),
                    available
                    - len(template_used)
                    - len(_ANALYSIS_TRUNCATION_SUFFIX),
                )
                if relocate_preserved:
                    analysis_content = _truncate_analysis_preserving_graph(
                        main, preserved, max_analysis
                    )
                else:
                    suffix_len = len(_ANALYSIS_TRUNCATION_SUFFIX)
                    if len(analysis_content) > max_analysis:
                        if max_analysis <= suffix_len:
                            analysis_content = _ANALYSIS_TRUNCATION_SUFFIX.strip()
                        else:
                            analysis_content = (
                                analysis_content[: max_analysis - suffix_len]
                                + _ANALYSIS_TRUNCATION_SUFFIX
                            )
                prompt = _build(template_used, analysis_content)
                continue

            if relocate_preserved:
                _, preserved_live = _split_preserved_sections(analysis_content)
                main_live = analysis_content[
                    : len(analysis_content) - len(preserved_live)
                ]
                if len(main_live) > len(_ANALYSIS_TRUNCATION_SUFFIX) + 32:
                    previous_len = len(prompt)
                    main_live = main_live[: max(0, len(main_live) - 256)]
                    if not main_live.endswith(_ANALYSIS_TRUNCATION_SUFFIX):
                        main_live += _ANALYSIS_TRUNCATION_SUFFIX
                    analysis_content = main_live + preserved_live
                    prompt = _build(template_used, analysis_content)
                    continue
            elif len(analysis_content) > len(_ANALYSIS_TRUNCATION_SUFFIX) + 32:
                previous_len = len(prompt)
                analysis_content = analysis_content[: max(0, len(analysis_content) - 256)]
                if not analysis_content.endswith(_ANALYSIS_TRUNCATION_SUFFIX):
                    analysis_content += _ANALYSIS_TRUNCATION_SUFFIX
                prompt = _build(template_used, analysis_content)
                continue

            self.logger.warning(
                "prompt exceeds alignment cap after assembly label=%s "
                "prompt_length=%d budget=%d -- cannot shrink further without "
                "dropping graph evidence",
                log_label,
                len(prompt),
                max_total,
            )
            break

        if len(prompt) > max_total:
            self.logger.warning(
                "prompt hard-truncating label=%s prompt_length=%d budget=%d",
                log_label,
                len(prompt),
                max_total,
            )
            if relocate_preserved:
                _, preserved_live = _split_preserved_sections(analysis_content)
                while (
                    len(prompt) > max_total
                    and len(analysis_content)
                    > len(preserved_live) + len(_ANALYSIS_TRUNCATION_SUFFIX)
                ):
                    main_live = analysis_content[
                        : len(analysis_content) - len(preserved_live)
                    ]
                    main_live = main_live[: max(0, len(main_live) - 512)]
                    if not main_live.endswith(_ANALYSIS_TRUNCATION_SUFFIX):
                        main_live += _ANALYSIS_TRUNCATION_SUFFIX
                    analysis_content = main_live + preserved_live
                    prompt = _build(template_used, analysis_content)
            else:
                while (
                    len(prompt) > max_total
                    and len(analysis_content) > len(_ANALYSIS_TRUNCATION_SUFFIX)
                ):
                    analysis_content = analysis_content[
                        : max(0, len(analysis_content) - 512)
                    ]
                    if not analysis_content.endswith(_ANALYSIS_TRUNCATION_SUFFIX):
                        analysis_content += _ANALYSIS_TRUNCATION_SUFFIX
                    prompt = _build(template_used, analysis_content)
            if len(prompt) > max_total:
                prompt = _cap_prompt_preserving_end_tag(
                    prompt, max_total=max_total, end_tag=end_tag
                )

        self.logger.debug(
            "prompt built label=%s prompt_length=%d analysis_content_length=%d "
            "preserved_length=%d pinned_length=%d",
            log_label,
            len(prompt),
            len(analysis_content),
            len(preserved),
            pinned_len,
        )
        return prompt

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
            if call.get("calls"):
                result += self._format_call_chain(call["calls"], indent + 3)
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
            prompt_file = (
                MCPScannerConstants.get_prompts_path()
                / "code_alignment_threat_analysis_prompt.md"
            )

            if not prompt_file.is_file():
                raise FileNotFoundError(
                    "Prompt file not found: code_alignment_threat_analysis_prompt.md"
                )

            return prompt_file.read_text(encoding="utf-8")

        except FileNotFoundError:
            self.logger.error(
                "Prompt file not found: code_alignment_threat_analysis_prompt.md"
            )
            raise
        except Exception as e:
            self.logger.error(
                f"Failed to load prompt code_alignment_threat_analysis_prompt.md: {e}"
            )
            raise IOError(
                f"Could not load prompt code_alignment_threat_analysis_prompt.md: {e}"
            )
