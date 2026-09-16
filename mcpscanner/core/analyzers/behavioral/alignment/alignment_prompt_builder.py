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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .....config.constants import MCPScannerConstants
from .....utils.log_format import truncate
from ....static_analysis.context_extractor import FunctionContext

_GRAPH_EVIDENCE_HEADER = "\n**CODE GRAPH EVIDENCE (deterministic static analysis):**\n"
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
                else 1 if header == _GRAPH_EVIDENCE_HEADER else 2
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


def _truncate_with_suffix(text: str, limit: int) -> str:
    """Cut ``text`` to ``limit``, spending the tail on the truncation notice.

    A limit too small to hold the notice yields the bare notice: saying the
    text was cut matters more than the handful of characters that would fit.
    """
    suffix_len = len(_ANALYSIS_TRUNCATION_SUFFIX)
    if limit <= suffix_len:
        return _ANALYSIS_TRUNCATION_SUFFIX.strip()
    return text[: limit - suffix_len] + _ANALYSIS_TRUNCATION_SUFFIX


def _shave(text: str, amount: int) -> str:
    """Drop ``amount`` characters off the end, keeping the truncation notice."""
    text = text[: max(0, len(text) - amount)]
    if not text.endswith(_ANALYSIS_TRUNCATION_SUFFIX):
        text += _ANALYSIS_TRUNCATION_SUFFIX
    return text


@dataclass
class _PromptFit:
    """Working state while fitting one prompt into the alignment budget.

    ``guidance`` is the truncatable head of the template and ``pinned`` the
    response schema that must survive intact; ``main`` and ``preserved`` are
    the same split applied to the analysis, where ``preserved`` holds the
    deterministic graph evidence. ``main`` and ``preserved`` are only
    populated when the caller asked to relocate preserved sections -- without
    that, ``analysis`` is one opaque string and truncation just eats its tail.
    """

    prefix: str
    start_tag: str
    end_tag: str
    log_label: str
    relocate_preserved: bool
    max_total: int
    available: int
    guidance: str
    pinned: str
    guidance_used: str
    main: str
    preserved: str
    analysis: str

    @property
    def template_used(self) -> str:
        return self.guidance_used + self.pinned

    def max_analysis(self) -> int:
        """How many characters the analysis may use, given the template.

        Never drops below the preserved length: graph evidence is not
        negotiable, and a caller that cannot fit it will hard-cap instead.
        """
        return max(
            len(self.preserved),
            self.available - len(self.template_used) - len(_ANALYSIS_TRUNCATION_SUFFIX),
        )

    def fit_analysis(self, limit: int) -> str:
        """Render the analysis body cut down to ``limit`` characters."""
        if self.relocate_preserved:
            return _truncate_analysis_preserving_graph(self.main, self.preserved, limit)
        if len(self.analysis) <= limit:
            return self.analysis
        return _truncate_with_suffix(self.analysis, limit)

    def shave_analysis(self, amount: int, *, floor: int) -> bool:
        """Take another bite out of the analysis, reporting whether it moved.

        Only the text before the preserved sections is eaten, so repeated
        calls converge on "graph evidence and nothing else" rather than on
        the empty string. Returns False once what remains is down to
        ``floor``, which is how the callers know to stop asking.
        """
        target = self.analysis
        preserved_live = ""
        if self.relocate_preserved:
            _, preserved_live = _split_preserved_sections(self.analysis)
            target = self.analysis[: len(self.analysis) - len(preserved_live)]

        if len(target) <= floor:
            return False

        self.analysis = _shave(target, amount) + preserved_live
        return True

    def build(self) -> str:
        """Frame the template and analysis into the final prompt string."""
        return (
            f"""{self.template_used}

{self.prefix}{self.start_tag}
{self.analysis}
{self.end_tag}
"""
        ).strip()


def _cap_prompt_preserving_end_tag(prompt: str, *, max_total: int, end_tag: str) -> str:
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

        if summary.get("code_graph_status") == "entry_unresolved":
            parts.append(
                "\n**CODE GRAPH STATUS:** entry_unresolved — static graph could not "
                "map this MCP function to a graph node; rely on other evidence.\n"
            )

        return "".join(parts)

    def build_analysis_content(self, func_context: FunctionContext) -> str:
        """Build deterministic alignment evidence (no random delimiters).

        Each section is a builder returning its text, or ``None`` when it has
        no evidence to contribute. Listing the builders here rather than
        appending to an accumulator is the point: the one bug this function
        has produced was a section built into a local list and then never
        appended, which this shape makes impossible.
        """
        builders = (
            self._section_entry_point,
            self._section_imports,
            self._section_dataflow_preamble,
            self._section_parameter_flows,
            self._section_variable_dependencies,
            self._section_function_calls,
            self._section_assignments,
            self._section_control_flow,
            self._section_cross_file_calls,
            self._section_reachability,
            self._section_constants,
            self._section_string_literals,
            self._section_return_expressions,
            self._section_exception_handlers,
            self._section_env_var_access,
            self._section_global_writes,
            self._section_attribute_writes,
            self._format_graph_evidence_section,
        )
        return "".join(
            section
            for section in (build(func_context) for build in builders)
            if section
        )

    def _section_entry_point(self, func_context: FunctionContext) -> Optional[str]:
        """Function identity, docstring and signature. Always present."""
        docstring = func_context.docstring or "No docstring provided"
        decorator = (
            func_context.decorator_types[0]
            if func_context.decorator_types
            else "unknown"
        )
        return f"""**ENTRY POINT INFORMATION:**
- Function Name: {func_context.name}
- Decorator: {decorator}
- Line: {func_context.line_number}
- Docstring/Description: {docstring}



**FUNCTION SIGNATURE:**
- Parameters: {json.dumps(func_context.parameters, indent=2)}
- Return Type: {func_context.return_type or 'Not specified'}
"""

    def _section_imports(self, func_context: FunctionContext) -> Optional[str]:
        """Libraries the function pulls in."""
        if not func_context.imports:
            return None

        import_parts = ["\n**IMPORTS:**\n"]
        import_parts.append("The following libraries and modules are imported:\n")
        for imp in func_context.imports:
            import_parts.append(f"  {imp}\n")
        import_parts.append("\n")
        return "".join(import_parts)

    def _section_dataflow_preamble(
        self, func_context: FunctionContext
    ) -> Optional[str]:
        """States the untrusted-input assumption. Always present."""
        return """
**DATAFLOW ANALYSIS:**
All parameters are treated as untrusted input (MCP entry points receive external data).

Parameter Flow Tracking:
"""

    def _section_parameter_flows(self, func_context: FunctionContext) -> Optional[str]:
        """Where each parameter travels and what it reaches."""
        if not func_context.parameter_flows:
            return None

        param_parts = ["\n**PARAMETER FLOW TRACKING:**\n"]
        for flow in func_context.parameter_flows:
            param_name = flow.get("parameter", "unknown")
            param_parts.append(f"\nParameter '{param_name}' flows through:\n")

            if flow.get("operations"):
                param_parts.append(f"  Operations ({len(flow['operations'])} total):\n")
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
                    "  ⚠️  REACHES EXTERNAL OPERATIONS (file/network/subprocess)\n"
                )

            if flow.get("reaches_returns"):
                param_parts.append("  Returns to caller\n")

        return "".join(param_parts)

    def _section_variable_dependencies(
        self, func_context: FunctionContext
    ) -> Optional[str]:
        """Which variables derive from which."""
        if not func_context.variable_dependencies:
            return None

        var_parts = ["\n**VARIABLE DEPENDENCIES:**\n"]
        for var, deps in func_context.variable_dependencies.items():
            var_parts.append(f"  {var} depends on: {', '.join(deps)}\n")
        return "".join(var_parts)

    def _section_function_calls(self, func_context: FunctionContext) -> Optional[str]:
        """Calls made, capped at ``MAX_FUNCTION_CALLS``."""
        if not func_context.function_calls:
            return None

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
            except Exception as exc:
                self.logger.debug(
                    "alignment prompt skipped_malformed kind=function_call error_type=%s error=%s",
                    type(exc).__name__,
                    truncate(exc),
                )
                continue
        return "".join(call_parts)

    def _section_assignments(self, func_context: FunctionContext) -> Optional[str]:
        """Assignments made, capped at ``MAX_ASSIGNMENTS``."""
        if not func_context.assignments:
            return None

        assign_parts = [f"\n**ASSIGNMENTS ({len(func_context.assignments)} total):**\n"]
        for assign in func_context.assignments[: self.MAX_ASSIGNMENTS]:
            try:
                line = assign.get("line", 0)
                var = assign.get("variable", "unknown")
                val = assign.get("value", "unknown")
                assign_parts.append(f"  Line {line}: {var} = {val}\n")
            except Exception as exc:
                self.logger.debug(
                    "alignment prompt skipped_malformed kind=assignment error_type=%s error=%s",
                    type(exc).__name__,
                    truncate(exc),
                )
                continue
        return "".join(assign_parts)

    def _section_control_flow(self, func_context: FunctionContext) -> Optional[str]:
        """Branching structure as raw JSON."""
        if not func_context.control_flow:
            return None

        return (
            f"\n**CONTROL FLOW:**\n{json.dumps(func_context.control_flow, indent=2)}\n"
        )

    def _section_cross_file_calls(self, func_context: FunctionContext) -> Optional[str]:
        """Calls leaving this file, with their transitive chains."""
        if not func_context.cross_file_calls:
            return None

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
            except Exception as exc:
                self.logger.debug(
                    "alignment prompt skipped_malformed kind=cross_file_call error_type=%s error=%s",
                    type(exc).__name__,
                    truncate(exc),
                )
                continue
        cross_file_parts.append(
            "Note: Analyze the entire call chain to understand what operations are performed.\n"
        )
        return "".join(cross_file_parts)

    def _section_reachability(self, func_context: FunctionContext) -> Optional[str]:
        """Reachable functions, grouped by file.

        Omitted when everything reachable lives in the current file, where
        the grouping is noise rather than evidence."""
        if not func_context.reachable_functions:
            return None

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
            reach_parts = ["\n**REACHABILITY ANALYSIS:**\n"]
            reach_parts.append(
                f"Total reachable functions: {total_reachable} across {len(functions_by_file)} file(s)\n\n"
            )
            for file_path, funcs in list(functions_by_file.items())[
                : self.MAX_REACHABLE_FILES
            ]:
                file_name = file_path.split("/")[-1] if "/" in file_path else file_path
                reach_parts.append(f"  {file_name}: {', '.join(funcs[:10])}\n")
                if len(funcs) > 10:
                    reach_parts.append(f"    ... and {len(funcs) - 10} more\n")
            return "".join(reach_parts)

    def _section_constants(self, func_context: FunctionContext) -> Optional[str]:
        """Constant values defined in the function."""
        if not func_context.constants:
            return None

        const_parts = ["\n**CONSTANTS:**\n"]
        for var, val in list(func_context.constants.items())[: self.MAX_CONSTANTS]:
            const_parts.append(f"  {var} = {val}\n")
        return "".join(const_parts)

    def _section_string_literals(self, func_context: FunctionContext) -> Optional[str]:
        """String literals, escaped and truncated. A high-value indicator."""
        if not func_context.string_literals:
            return None

        lit_parts = [
            f"\n**STRING LITERALS ({len(func_context.string_literals)} total):**\n"
        ]
        for literal in func_context.string_literals[: self.MAX_STRING_LITERALS]:
            # Escape and truncate for safety
            safe_literal = literal.replace("\n", "\\n").replace("\r", "\\r")[:150]
            lit_parts.append(f'  "{safe_literal}"\n')
        return "".join(lit_parts)

    def _section_return_expressions(
        self, func_context: FunctionContext
    ) -> Optional[str]:
        """What the function returns, and its declared type."""
        if not func_context.return_expressions:
            return None

        ret_parts = ["\n**RETURN EXPRESSIONS:**\n"]
        if func_context.return_type:
            ret_parts.append(f"Declared return type: {func_context.return_type}\n")
        for ret_expr in func_context.return_expressions:
            ret_parts.append(f"  return {ret_expr}\n")
        return "".join(ret_parts)

    def _section_exception_handlers(
        self, func_context: FunctionContext
    ) -> Optional[str]:
        """Handlers, flagging any that silently swallow."""
        if not func_context.exception_handlers:
            return None

        exc_parts = ["\n**EXCEPTION HANDLING:**\n"]
        for handler in func_context.exception_handlers:
            exc_type = handler.get("exception_type", "Exception")
            line = handler.get("line", "?")
            exc_parts.append(f"  Line {line}: except {exc_type}")
            if handler.get("is_silent", False):
                exc_parts.append(" (⚠️  SILENT - just 'pass')\n")
            else:
                exc_parts.append("\n")
        return "".join(exc_parts)

    def _section_env_var_access(self, func_context: FunctionContext) -> Optional[str]:
        """Environment variables the function reads."""
        if not func_context.env_var_access:
            return None

        env_parts = ["\n**ENVIRONMENT VARIABLE ACCESS:**\n"]
        env_parts.append("⚠️  This function accesses environment variables:\n")
        for env_access in func_context.env_var_access:
            env_parts.append(f"  {env_access}\n")
        return "".join(env_parts)

    def _section_global_writes(self, func_context: FunctionContext) -> Optional[str]:
        """Global state the function modifies."""
        if not func_context.global_writes:
            return None

        global_parts = ["\n**GLOBAL VARIABLE WRITES:**\n"]
        global_parts.append("⚠️  This function modifies global state:\n")
        for gwrite in func_context.global_writes:
            global_parts.append(
                f"  Line {gwrite['line']}: global {gwrite['variable']} = {gwrite['value']}\n"
            )
        return "".join(global_parts)

    def _section_attribute_writes(self, func_context: FunctionContext) -> Optional[str]:
        """Attribute writes only; reads are not evidence of mutation."""
        if not func_context.attribute_access:
            return None

        writes = [
            op for op in func_context.attribute_access if op.get("type") == "write"
        ]
        if writes:
            attr_parts = ["\n**ATTRIBUTE WRITES:**\n"]
            for op in writes[:10]:
                line = op.get("line", "?")
                obj = op.get("object", "?")
                attr = op.get("attribute", "?")
                val = op.get("value", "?")
                attr_parts.append(f"  Line {line}: {obj}.{attr} = {val}\n")
            return "".join(attr_parts)

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

    def build_batch_analysis_content(self, func_contexts: List[FunctionContext]) -> str:
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

            all_content.append(f"=== FUNCTION {idx + 1} of {len(func_contexts)} ===\n")
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
                all_content.append(f"**Security Flags:** {', '.join(security_flags)}\n")

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
        """Build the final prompt and enforce the alignment context budget.

        Fitting happens in four stages, each giving up less than the last:
        trim the template guidance, trim the analysis, shrink both in a loop
        while the assembled prompt is still over, and finally hard-cap the
        string. Graph evidence is held back from every stage when
        ``relocate_preserved`` is set, because a prompt that lost its
        deterministic evidence is worse than a shorter one.
        """
        fit = self._plan_prompt_fit(
            template=template,
            analysis_content=analysis_content,
            start_tag=start_tag,
            end_tag=end_tag,
            log_label=log_label,
            prefix=prefix,
            relocate_preserved=relocate_preserved,
        )
        self._trim_guidance(fit)
        self._trim_analysis(fit, analysis_content)

        prompt = fit.build()
        prompt = self._shrink_to_fit(fit, prompt)
        prompt = self._hard_cap(fit, prompt)

        self.logger.debug(
            "prompt built label=%s prompt_length=%d analysis_content_length=%d "
            "preserved_length=%d pinned_length=%d",
            fit.log_label,
            len(prompt),
            len(fit.analysis),
            len(fit.preserved),
            len(fit.pinned),
        )
        return prompt

    @staticmethod
    def _plan_prompt_fit(
        *,
        template: str,
        analysis_content: str,
        start_tag: str,
        end_tag: str,
        log_label: str,
        prefix: str,
        relocate_preserved: bool,
    ) -> "_PromptFit":
        """Work out the character budget and split the inputs along it."""
        max_total = MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS
        frame_overhead = (
            len(prefix) + len(start_tag) + len(end_tag) + _PROMPT_FRAME_CHARS
        )
        available = max(0, max_total - frame_overhead)

        guidance, pinned = _split_template(template)

        main = ""
        preserved = ""
        if relocate_preserved:
            main, preserved = _split_preserved_sections(analysis_content)
            preserved = _cap_preserved_sections(
                preserved,
                min(_MAX_PRESERVED_TOTAL_CHARS, max(len(preserved), available // 3)),
            )

        return _PromptFit(
            prefix=prefix,
            start_tag=start_tag,
            end_tag=end_tag,
            log_label=log_label,
            relocate_preserved=relocate_preserved,
            max_total=max_total,
            available=available,
            guidance=guidance,
            pinned=pinned,
            guidance_used=guidance,
            main=main,
            preserved=preserved,
            analysis=analysis_content,
        )

    def _trim_guidance(self, fit: "_PromptFit") -> None:
        """Cut the truncatable head of the template down to its share."""
        reserved_analysis = (
            len(fit.pinned)
            + len(fit.preserved)
            + _MIN_ANALYSIS_CHARS
            + len(_ANALYSIS_TRUNCATION_SUFFIX)
        )
        max_guidance_len = max(0, fit.available - reserved_analysis)
        if len(fit.guidance) <= max_guidance_len:
            return

        allow = max(0, max_guidance_len - len(_TEMPLATE_TRUNCATION_SUFFIX))
        fit.guidance_used = fit.guidance[:allow] + _TEMPLATE_TRUNCATION_SUFFIX
        self.logger.warning(
            "prompt template truncated label=%s template_length=%d "
            "max_guidance=%d pinned=%d budget=%d preserved_reserved=%d",
            fit.log_label,
            len(fit.guidance),
            max_guidance_len,
            len(fit.pinned),
            fit.max_total,
            len(fit.preserved),
        )

    def _trim_analysis(self, fit: "_PromptFit", original: str) -> None:
        """Cut the analysis body down to whatever the template left it."""
        max_analysis = fit.max_analysis()

        if fit.relocate_preserved:
            if len(original) <= max_analysis:
                fit.analysis = original
                return
            if len(fit.main) + len(fit.preserved) <= max_analysis:
                fit.analysis = fit.main + fit.preserved
                return
        elif len(fit.analysis) <= max_analysis:
            return

        self._warn_analysis_truncated(fit, len(original), max_analysis)
        fit.analysis = fit.fit_analysis(max_analysis)

    def _warn_analysis_truncated(
        self, fit: "_PromptFit", analysis_length: int, max_analysis: int
    ) -> None:
        self.logger.warning(
            "prompt truncated label=%s analysis_length=%d max_analysis=%d "
            "budget=%d preserved=%d pinned=%d",
            fit.log_label,
            analysis_length,
            max_analysis,
            fit.max_total,
            len(fit.preserved),
            len(fit.pinned),
        )

    def _shrink_to_fit(self, fit: "_PromptFit", prompt: str) -> str:
        """Alternate between shrinking guidance and analysis until it fits.

        ``previous_len`` guards the guidance step: once a pass fails to make
        the prompt any shorter, stop retrying it and start eating the
        analysis instead, so a body that cannot shrink cannot spin forever.
        """
        previous_len: Optional[int] = None
        while len(prompt) > fit.max_total:
            guidance_body = fit.guidance_used
            if guidance_body.endswith(_TEMPLATE_TRUNCATION_SUFFIX):
                guidance_body = guidance_body[: -len(_TEMPLATE_TRUNCATION_SUFFIX)]

            if len(guidance_body) > 0 and previous_len != len(prompt):
                previous_len = len(prompt)
                new_len = max(
                    0, len(guidance_body) - max(256, len(guidance_body) // 10)
                )
                if new_len < len(fit.guidance):
                    fit.guidance_used = (
                        fit.guidance[:new_len] + _TEMPLATE_TRUNCATION_SUFFIX
                    )
                else:
                    fit.guidance_used = guidance_body[:new_len]
                fit.analysis = fit.fit_analysis(fit.max_analysis())
                prompt = fit.build()
                continue

            if fit.shave_analysis(256, floor=len(_ANALYSIS_TRUNCATION_SUFFIX) + 32):
                previous_len = len(prompt)
                prompt = fit.build()
                continue

            self.logger.warning(
                "prompt exceeds alignment cap after assembly label=%s "
                "prompt_length=%d budget=%d -- cannot shrink further without "
                "dropping graph evidence",
                fit.log_label,
                len(prompt),
                fit.max_total,
            )
            break
        return prompt

    def _hard_cap(self, fit: "_PromptFit", prompt: str) -> str:
        """Last resort: shave in bigger steps, then cut the string outright."""
        if len(prompt) <= fit.max_total:
            return prompt

        self.logger.warning(
            "prompt hard-truncating label=%s prompt_length=%d budget=%d",
            fit.log_label,
            len(prompt),
            fit.max_total,
        )
        while len(prompt) > fit.max_total and fit.shave_analysis(
            512, floor=len(_ANALYSIS_TRUNCATION_SUFFIX)
        ):
            prompt = fit.build()

        if len(prompt) > fit.max_total:
            prompt = _cap_prompt_preserving_end_tag(
                prompt, max_total=fit.max_total, end_tag=fit.end_tag
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
