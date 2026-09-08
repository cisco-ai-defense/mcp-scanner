# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Resolve dynamic call sites when the receiver or method name is partially static."""

from __future__ import annotations

import ast
import re

from ..semantic.treesitter_analyzer import TreeSitterSemanticAnalyzer
from ..semantic.type_analyzer import TypeAnalyzer
from .semantic_dispatch import DispatchResult, ProgramFacts, SemanticDispatchEngine

_DYNAMIC_CALL_RE = re.compile(r"\[.*\]|getattr|\.send\(|->\$|call\(|apply\(|bind\(")
_BRACKET_LITERAL_RE = re.compile(r"""^([\w$]+)\[(['"])([^'"]+)\2\]$""")
_GETATTR_LITERAL_RE = re.compile(r"""^getattr\(\s*([\w$]+)\s*,\s*(['"])([^'"]+)\2""")
_BRACKET_VAR_RE = re.compile(r"^([\w$]+)\[[\w$]+\]$")
_BRACKET_CALL_RE = re.compile(
    r"^(?P<recv>.+?)\[(?P<key>['\"](?P<lit>[^'\"]+)['\"]|(?P<var>[\w$]+))\]$"
)
_TS_CAST_RECEIVER_RE = re.compile(r"^\(\s*([\w$]+)\s+as\s+[^)]+\)$")
_PAREN_RECEIVER_RE = re.compile(r"^\(\s*([\w$]+)\s*\)$")
_GETATTR_VAR_RE = re.compile(r"^getattr\(\s*([\w$]+)\s*,\s*([\w$]+)\s*\)?$")
_SEND_VAR_RE = re.compile(r"^([\w$]+)\.send\(([\w$]+)\)$")
_PHP_VAR_METHOD_RE = re.compile(r"^(\$\w+)->\$(\w+)$")
_APPLY_RE = re.compile(r"^([\w$.]+)\.(call|apply|bind)\(")


def _normalize_receiver(expr: str) -> str | None:
    """
    Normalize a receiver expression to its bare identifier.
    
    Parameters:
        expr (str): Receiver expression, optionally wrapped in parentheses or a TypeScript cast.
    
    Returns:
        str | None: The bare identifier, or `None` if the expression has another form.
    """
    text = expr.strip()
    match = _TS_CAST_RECEIVER_RE.match(text)
    if match:
        return match.group(1)
    match = _PAREN_RECEIVER_RE.match(text)
    if match:
        return match.group(1)
    if re.match(r"^[\w$]+$", text):
        return text
    return None


def _parse_bracket_call(label: str) -> tuple[str | None, str | None, str] | None:
    """
    Parse bracket-based dynamic call syntax and classify the key as literal or variable.
    
    Parameters:
    	label (str): A receiver bracket expression, such as ``receiver[key]``.
    
    Returns:
    	tuple[str | None, str | None, str] | None: The normalized receiver, literal method name when present, and call kind; ``None`` when the expression is unsupported.
    """
    match = _BRACKET_CALL_RE.match(label)
    if not match:
        return None
    receiver = _normalize_receiver(match.group("recv"))
    if not receiver:
        return None
    if match.group("lit") is not None:
        return receiver, match.group("lit"), "bracket_literal"
    return receiver, None, "bracket_variable"


def is_dynamic_call_label(callee_label: str) -> bool:
    """
    Determine whether a callee label contains recognized dynamic-call syntax.
    
    Parameters:
    	callee_label (str): Callee label to inspect.
    
    Returns:
    	bool: `true` if the label contains recognized dynamic-call syntax, `false` otherwise.
    """
    return bool(_DYNAMIC_CALL_RE.search(callee_label))


def parse_dynamic_call(callee_label: str) -> tuple[str | None, str | None, str] | None:
    """
    Parse a dynamic call label into its receiver, method, and call kind.
    
    Parameters:
    	callee_label (str): The call label to classify.
    
    Returns:
    	tuple[str | None, str | None, str] | None: The receiver, method when available, and dynamic call kind; `(None, None, "unknown")` for recognized but unparsable syntax; `None` for ordinary call labels.
    """
    label = callee_label.strip()
    if label.endswith("()"):
        label = label[:-2]

    bracket = _parse_bracket_call(label)
    if bracket is not None:
        return bracket

    match = _BRACKET_LITERAL_RE.match(label)
    if match:
        return match.group(1), match.group(3), "bracket_literal"

    match = _GETATTR_LITERAL_RE.match(label)
    if match:
        return match.group(1), match.group(3), "getattr_literal"

    match = _BRACKET_VAR_RE.match(label)
    if match:
        return match.group(1), None, "bracket_variable"

    match = _GETATTR_VAR_RE.match(label)
    if match:
        return match.group(1), None, "getattr_variable"

    match = _SEND_VAR_RE.match(label)
    if match:
        return match.group(1), None, "send_variable"

    match = _PHP_VAR_METHOD_RE.match(label)
    if match:
        return match.group(1), None, "php_variable_method"

    match = _APPLY_RE.match(label)
    if match:
        return match.group(1), None, match.group(2)

    if is_dynamic_call_label(label):
        return None, None, "unknown"
    return None


def resolve_dynamic_dispatch(
    callee_label: str,
    *,
    language: str,
    source: str | None,
    caller_label: str,
    caller_file: str,
    semantic: TypeAnalyzer | TreeSitterSemanticAnalyzer | None,
    known_functions: set[str],
    program_facts: ProgramFacts | None = None,
    caller_node_id: str | None = None,
) -> DispatchResult:
    """
    Resolve a dynamic or virtual call label using semantic dispatch information.
    
    Parameters:
        callee_label (str): The called expression to classify and resolve.
        source (str | None): Source code containing the call.
        caller_label (str): Label identifying the calling function or context.
        caller_file (str): File containing the caller.
        known_functions (set[str]): Known function names available for dispatch.
        caller_node_id (str | None): Optional identifier of the caller's syntax node.
    
    Returns:
        DispatchResult: Resolved dispatch targets and associated metadata, or an empty result when the label is unsupported or source is unavailable.
    """
    parsed = parse_dynamic_call(callee_label)
    if parsed is None:
        return DispatchResult()

    receiver, method, kind = parsed
    if source is None:
        return DispatchResult()

    engine = SemanticDispatchEngine.for_file(
        language=language,
        source=source,
        known_functions=known_functions,
        caller_file=caller_file,
        semantic=semantic,
        program_facts=program_facts,
        caller_node_id=caller_node_id,
    )
    return engine.resolve(
        caller_label=caller_label,
        callee_label=callee_label,
        receiver=receiver,
        method=method,
        kind=kind,
    )


def resolve_virtual_dispatch(
    callee_label: str,
    *,
    language: str,
    source: str | None,
    caller_label: str,
    caller_file: str,
    semantic: TypeAnalyzer | TreeSitterSemanticAnalyzer | None,
    known_functions: set[str],
    program_facts: ProgramFacts | None = None,
    caller_node_id: str | None = None,
) -> DispatchResult:
    """
    Resolve virtual dispatch for receiver-method call labels.
    
    Parameters:
        callee_label (str): Static-looking receiver-method call label.
        source (str | None): Source text containing the call.
        caller_label (str): Label identifying the calling function.
        caller_file (str): Path of the file containing the caller.
    
    Returns:
        DispatchResult: Resolved virtual-dispatch targets, or an empty result when
            the source is unavailable or the callee label contains no dot.
    """
    if source is None or "." not in callee_label:
        return DispatchResult()
    engine = SemanticDispatchEngine.for_file(
        language=language,
        source=source,
        known_functions=known_functions,
        caller_file=caller_file,
        semantic=semantic,
        program_facts=program_facts,
        caller_node_id=caller_node_id,
    )
    return engine.resolve_virtual_method(caller_label=caller_label, callee_label=callee_label)


def resolve_python_dynamic_call(
    callee_label: str,
    *,
    source: str,
    caller_label: str,
    semantic: TypeAnalyzer | None,
    known_functions: set[str],
    caller_file: str,
    program_facts: ProgramFacts | None = None,
    caller_node_id: str | None = None,
) -> DispatchResult:
    """
    Resolve a Python dynamic call using available program and semantic information.
    
    Parameters:
    	callee_label (str): Label describing the called expression.
    	source (str): Source code containing the call.
    	caller_label (str): Label identifying the calling function.
    	known_functions (set[str]): Known function names used during dispatch resolution.
    	caller_file (str): File containing the caller.
    	program_facts (ProgramFacts | None): Optional program facts used for resolution.
    	caller_node_id (str | None): Optional identifier of the caller's graph node.
    
    Returns:
    	DispatchResult: Dispatch resolution results for the Python call.
    """
    return resolve_dynamic_dispatch(
        callee_label,
        language="python",
        source=source,
        caller_label=caller_label,
        caller_file=caller_file,
        semantic=semantic,
        known_functions=known_functions,
        program_facts=program_facts,
        caller_node_id=caller_node_id,
    )


def resolve_dynamic_call(
    callee_label: str,
    *,
    semantic: TypeAnalyzer | TreeSitterSemanticAnalyzer | None,
    known_functions: set[str],
    caller_file: str,
    language: str = "typescript",
    source: str | None = None,
    caller_label: str = "",
) -> tuple[str, float, str] | None:
    """
    Resolve a dynamic call to its primary target.
    
    Parameters:
    	callee_label (str): Label identifying the dynamic call.
    	caller_file (str): File containing the call site.
    	language (str): Language of the call expression.
    	source (str | None): Source text containing the call, when available.
    	caller_label (str): Label identifying the caller.
    
    Returns:
    	tuple[str, float, str] | None: The primary target's node ID, confidence, and context, or `None` when no target is found.
    """
    result = resolve_dynamic_dispatch(
        callee_label,
        language=language,
        source=source,
        caller_label=caller_label,
        caller_file=caller_file,
        semantic=semantic,
        known_functions=known_functions,
    )
    primary = result.primary()
    if primary is None:
        return None
    return primary.node_id, primary.confidence, primary.context


def _python_call_label(node: ast.Call) -> str | None:
    """Return the source-style label for a Python call's function expression.
    
    Parameters:
    	node (ast.Call): The call expression to unparse.
    
    Returns:
    	str | None: The unparsed function label, or `None` if the expression cannot be unparsed.
    """
    try:
        return ast.unparse(node.func)
    except (AttributeError, TypeError, ValueError):
        return None
