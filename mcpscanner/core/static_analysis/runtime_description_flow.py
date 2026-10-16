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

"""Follow tool-description changes through helper functions and across files.

A rug pull rarely sits next to the registration. The swap can live in a
helper (``arm(tool)`` whose body does ``t.description = ...``) or in a
module that imports the tool. Each file is reduced to a few facts —
description writes, function parameters, call sites, imports — which are
then propagated so a change lands on the tool it actually mutates.
"""

from __future__ import annotations

import ast
import logging
import os
import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from .context_extractor import FunctionContext

logger = logging.getLogger(__name__)

MAX_RUNTIME_DESCRIPTION_CHARS = 4000
# Budget for override text shown to the alignment check per tool. The prompt
# is truncated from the end and the description precedes the code, so
# unbounded override text could push the handler out of the prompt. Every
# override gets a share (head and tail) rather than later ones being
# dropped, so padding cannot hide a payload behind benign variants.
# The budget covers the whole block, headers included; only when every shown
# override is already at the minimum share can it be exceeded, by at most
# MAX_RUNTIME_OVERRIDES_SHOWN * (_MIN_OVERRIDE_SHARE + header) characters.
MAX_RUNTIME_OVERRIDE_TOTAL_CHARS = 12000
MAX_RUNTIME_OVERRIDES_SHOWN = 20
_MIN_OVERRIDE_SHARE = 200
_MAX_HEADER_DETAIL_CHARS = 200
_OVERRIDE_BLOCK_ATTR = "_runtime_override_block"
_SCHEMA_PATH_RE = re.compile(
    r"(?i)(?:^|[.\[])(?:input_?schema|output_?schema|schema|properties|parameters|params"
    r"|args|arguments|fields|items)\b"
)

_PROPAGATION_ROUNDS = 6
_HELPER_SEARCH_ROUNDS = 4
_MAX_IMPORT_HOPS = 5
_SELF_PREFIX_RE = re.compile(r"^(?:this|self|cls|\$this|@)(?:\.|->|::)?(?=[\$\w])")
_TARGET_SEP_RE = re.compile(r"\?\.|->|::|\.")
_COMPUTED_PREFIX = "<computed at runtime: "


def add_runtime_description_override(
    ctx: "FunctionContext",
    text: str,
    *,
    line_number: int,
    condition: Optional[str],
    mode: str,
    via: str,
    source_file: Optional[str] = None,
) -> None:
    """Record a runtime description change and show it to the alignment check.

    ``mode`` is ``"replace"``, ``"append"`` or ``"parameter"`` (a description
    inside the tool's input schema); ``via`` names the mechanism
    (``"__doc__ assignment"``, ``"description field write"``, ...).
    ``source_file`` is set when the change is made in another file. Every
    override is recorded and the docstring's override block is re-rendered
    within the display budget.
    """
    text = _clip(text or "", MAX_RUNTIME_DESCRIPTION_CHARS)
    if not text.strip():
        return
    for existing in ctx.runtime_docstring_overrides:
        if (
            existing["line_number"] == line_number
            and existing["text"] == text
            and existing.get("source_file") == source_file
        ):
            return
    override: Dict[str, Any] = {
        "line_number": line_number,
        "mode": mode,
        "condition": condition,
        "via": via,
        "text": text,
    }
    if source_file:
        override["source_file"] = source_file
    ctx.runtime_docstring_overrides.append(override)

    previous = getattr(ctx, _OVERRIDE_BLOCK_ATTR, "")
    base = ctx.docstring or ""
    if previous and base.endswith(previous):
        base = base[: -len(previous)]
    elif previous and previous in base:
        base = base.replace(previous, "", 1)
    block = _render_overrides(ctx.runtime_docstring_overrides)
    docstring = f"{base}{block}".lstrip()
    # Stored as it appears in the docstring: with an empty base the leading
    # blank lines are stripped.
    setattr(ctx, _OVERRIDE_BLOCK_ATTR, block if docstring.endswith(block) else docstring)
    ctx.docstring = docstring


def _render_overrides(overrides: List[Dict[str, Any]]) -> str:
    """Docstring block describing ``overrides`` within the display budget.

    Past :data:`MAX_RUNTIME_OVERRIDES_SHOWN`, the first and last halves are
    kept (the last write is the one in effect) and the rest counted.
    """
    shown = overrides
    omitted = 0
    if len(overrides) > MAX_RUNTIME_OVERRIDES_SHOWN:
        half = MAX_RUNTIME_OVERRIDES_SHOWN // 2
        shown = overrides[:half] + overrides[-half:]
        omitted = len(overrides) - len(shown)
    headers = [_override_header(o) for o in shown]
    room = MAX_RUNTIME_OVERRIDE_TOTAL_CHARS - sum(len(h) + 3 for h in headers)
    share = max(_MIN_OVERRIDE_SHARE, room // len(shown))
    parts = []
    for index, (header, override) in enumerate(zip(headers, shown)):
        if omitted and index == len(shown) // 2:
            parts.append(f"[{omitted} more runtime description overrides omitted]")
        parts.append(f"{header}\n{_clip(override['text'], share)}")
    return "".join(f"\n\n{part}" for part in parts)


def _override_header(override: Dict[str, Any]) -> str:
    where = f"line {override['line_number']}, {_clip(override['via'], _MAX_HEADER_DETAIL_CHARS)}"
    if override.get("source_file"):
        where = f"{_clip(os.path.basename(override['source_file']), _MAX_HEADER_DETAIL_CHARS)} {where}"
    if override.get("condition"):
        where += f", when `{_clip(override['condition'], _MAX_HEADER_DETAIL_CHARS)}`"
    if override["mode"] == "parameter":
        summary = "a parameter description the agent receives is set at runtime"
    else:
        verb = "extended" if override["mode"] == "append" else "replaced"
        summary = f"the tool description an agent receives is {verb} at runtime"
    return f"[Runtime description override ({where}): {summary} with the text below]"


def _clip(text: str, limit: int) -> str:
    """``text`` cut to ``limit`` characters keeping its head and tail."""
    if len(text) <= limit:
        return text
    marker = f" [...{len(text) - limit} chars omitted...] "
    room = max(0, limit - len(marker))
    head = room * 2 // 3
    return f"{text[:head]}{marker}{text[len(text) - (room - head):]}"


def describe_nested_write(nested: Optional[str]) -> Optional[Tuple[Optional[str], str]]:
    """``(mode override, via suffix)`` for a write on a field inside a tool.

    ``None`` nested path is the tool's own description. A path into the
    input schema is a parameter description; any other nested object's
    ``description`` is not the tool's and yields ``None``.
    """
    if nested is None:
        return None, ""
    if _SCHEMA_PATH_RE.search(nested):
        return "parameter", f" on {nested}"
    return None


# ---------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DescriptionWrite:
    """A description change whose target is an expression in some scope."""

    target: str
    text: str
    mode: str
    via: str
    line: int
    condition: Optional[str]
    enclosing: Optional[str] = None
    enclosing_params: Tuple[str, ...] = ()
    start_byte: int = -1
    text_expr: Optional[str] = None
    enclosing_class: Optional[str] = None
    # The receiver's head is declared in the write's own scope (a local or
    # parameter), so it cannot name another file's variable.
    local_head: bool = False
    # ``target`` with aliases resolved (``const a = factTool`` -> ``factTool``).
    alias: Optional[str] = None
    alias_local_head: bool = False
    # Tool object built as an argument of a registration call on a server
    # constructed in its own file: that file's tool, analyzed there, not a
    # redefinition elsewhere.
    registered: bool = False
    # Tool object passed straight to a registration call (on any server):
    # another registration of the tool rather than a bare redefinition.
    in_registration: bool = False


@dataclass(frozen=True)
class CallSite:
    callee: str
    args: Tuple[str, ...]
    values: Tuple[Optional[str], ...]
    kwargs: Tuple[Tuple[str, str, Optional[str]], ...]
    line: int
    condition: Optional[str]
    enclosing: Optional[str] = None
    enclosing_params: Tuple[str, ...] = ()
    start_byte: int = -1
    enclosing_class: Optional[str] = None


@dataclass
class FileFacts:
    path: str
    language: str
    functions: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    writes: List[DescriptionWrite] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    redefinitions: List[Tuple[str, DescriptionWrite]] = field(default_factory=list)
    imports: Dict[str, Tuple[str, Optional[str]]] = field(default_factory=dict)
    bound_names: Set[str] = field(default_factory=set)
    classes: Set[str] = field(default_factory=set)
    # Class name -> names of the methods it defines.
    methods: Dict[str, Set[str]] = field(default_factory=dict)
    # Variable -> class it is an instance of (``armer = Armer()``).
    instances: Dict[str, str] = field(default_factory=dict)
    # Function -> classes of the objects it may return (``func NewArmer() *Armer``).
    factories: Dict[str, List[str]] = field(default_factory=dict)
    # Class -> the classes it extends or embeds, as written in this file.
    bases: Dict[str, List[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class ParamWrite:
    """A function changes the description of the tool passed as ``param``."""

    param: int
    param_name: str
    text: Optional[str]
    text_param: Optional[int]
    text_param_name: Optional[str]
    mode: str
    via: str
    condition: Optional[str]
    origin: str
    helpers: Tuple[str, ...] = ()
    # Field path from the parameter to the written object
    # (``inputSchema.properties.q`` for ``t.inputSchema.properties.q.description``).
    path: str = ""
    # ``file:summary key`` of every function this write was summarized in;
    # stops recursive helpers without confusing same-named methods.
    chain: Tuple[str, ...] = field(default=(), compare=False)


@dataclass(frozen=True)
class DescriptionChange:
    """A resolved change: ``target`` names a tool in ``target_file``'s scope."""

    target: str
    text: str
    mode: str
    via: str
    line: int
    condition: Optional[str]
    file: str
    enclosing: Optional[str] = None
    start_byte: int = -1
    cross_file: bool = False
    local_head: bool = False
    alias: Optional[str] = None
    alias_local_head: bool = False


def split_target(expr: str) -> List[str]:
    return [p for p in _TARGET_SEP_RE.split(strip_self_prefix(expr.strip())) if p]


def strip_self_prefix(expr: str) -> str:
    return _SELF_PREFIX_RE.sub("", expr.strip(), count=1)


def computed_text(expr: str) -> str:
    return f"{_COMPUTED_PREFIX}{expr.strip()[:300]}>"


def computed_expr(text: str) -> Optional[str]:
    if text.startswith(_COMPUTED_PREFIX) and text.endswith(">"):
        return text[len(_COMPUTED_PREFIX) : -1].strip()
    return None


def _join_conditions(outer: Optional[str], inner: Optional[str]) -> Optional[str]:
    if outer and inner:
        return f"{outer} and {inner}"
    return outer or inner


def _call_argument(
    call: CallSite, index: int, name: Optional[str]
) -> Optional[Tuple[str, Optional[str]]]:
    if name:
        for key, text, value in call.kwargs:
            if key == name:
                return text, value
    if 0 <= index < len(call.args):
        return call.args[index], call.values[index]
    return None


def _last_segment(callee: str) -> Tuple[str, str]:
    parts = _TARGET_SEP_RE.split(callee.strip())
    return (parts[-1] if parts else callee), callee[: max(0, len(callee) - len(parts[-1]))]


_SELF_QUALIFIERS = {"this.", "self.", "cls.", "$this->", "self::", "static::", "Self::", "@"}
# ``super().``, ``super(Child, self).``, ``super.``, ``parent::`` (C# ``base.``
# only in C#, where it is a keyword)
_SUPER_QUALIFIER_RE = re.compile(r"^(?:super\s*\([^()]*\)\s*\.|super\.|parent::)$")
# Languages where an unqualified call inside a class can be one of its
# methods. Elsewhere (Python, JavaScript, PHP, Go, Rust) it is a free function.
_BARE_CALL_METHOD_LANGUAGES = frozenset({"java", "kotlin", "c_sharp", "swift", "ruby", "scala"})


def summary_key(function: Optional[str], cls: Optional[str]) -> str:
    """Summaries of methods are keyed ``Class.method`` so same-named methods
    of different classes stay apart."""
    return f"{cls}.{function}" if cls else (function or "")


def _with_path(expr: str, path: str) -> str:
    return f"{expr}.{path}" if path else expr


_CONSTRUCTED_RE = re.compile(r"^(?:new\s+)?([A-Za-z_$][\w$]*)\s*\(.*\)$", re.DOTALL)
_INSTANCE_RE = re.compile(
    r"(?<![\w$.])([\w$]+)\s*(?::\s*[\w$.<>?\[\]]+\s*)?(?::=|=)(?!=)\s*(?:new\s+)?([A-Z][\w$]*)\s*\("
)


def instance_class(facts: "FileFacts", qualifier: str) -> Optional[str]:
    """Class whose method ``qualifier.method(...)`` calls, when the qualifier
    is an instance (``armer.``) or a construction (``Armer().``)."""
    q = qualifier.strip()
    for sep in ("?.", "->", "::", "."):
        if q.endswith(sep):
            q = q[: -len(sep)]
            break
    constructed = _CONSTRUCTED_RE.match(q)
    if constructed:
        return constructed.group(1)
    return facts.instances.get(q)


def scan_instances(source: str) -> Dict[str, str]:
    """``x = Class(...)`` / ``x = new Class(...)`` / ``x := Class(...)``."""
    return {m.group(1): m.group(2) for m in _INSTANCE_RE.finditer(source)}

SummaryLookup = Callable[[FileFacts, CallSite], List[ParamWrite]]


def summarize(
    facts: FileFacts,
    summaries: Optional[Dict[str, Set[ParamWrite]]] = None,
    external: Optional[SummaryLookup] = None,
) -> Tuple[Dict[str, Set[ParamWrite]], List[DescriptionChange]]:
    """Helper summaries for ``facts`` and the changes they cause in its scope.

    A write whose receiver is a parameter of its enclosing function becomes a
    summary; calls to summarized functions become changes on the argument
    (or new summaries, when the argument is itself a parameter).
    """
    summaries = {k: set(v) for k, v in (summaries or {}).items()}
    changes: List[DescriptionChange] = []

    for write in facts.writes:
        target_parts = split_target(write.target) or [""]
        head = target_parts[0]
        params = write.enclosing_params
        if write.enclosing and head in params:
            text_param = (
                params.index(write.text_expr)
                if write.text_expr and write.text_expr in params
                else None
            )
            key = summary_key(write.enclosing, write.enclosing_class)
            summaries.setdefault(key, set()).add(
                ParamWrite(
                    param=params.index(head),
                    param_name=head,
                    text=None if text_param is not None else write.text,
                    text_param=text_param,
                    text_param_name=params[text_param] if text_param is not None else None,
                    mode=write.mode,
                    via=write.via,
                    condition=write.condition,
                    origin=facts.path,
                    path=".".join(target_parts[1:]),
                    chain=(f"{facts.path}:{key}",),
                )
            )
        else:
            changes.append(
                DescriptionChange(
                    target=write.target,
                    text=write.text,
                    mode=write.mode,
                    via=write.via,
                    line=write.line,
                    condition=write.condition,
                    file=facts.path,
                    enclosing=write.enclosing,
                    start_byte=write.start_byte,
                    local_head=write.local_head,
                    alias=write.alias,
                    alias_local_head=write.alias_local_head,
                )
            )

    def inherited(cls: str, name: str, call: CallSite) -> Tuple[List[ParamWrite], bool]:
        """Summaries of ``name`` as ``cls`` inherits it (from the nearest base
        defining it in this file, or from bases in other files) and whether
        a base defining it was found."""
        found: List[ParamWrite] = []
        defined = False
        queue, seen = list(facts.bases.get(cls, ())), {cls}
        while queue:
            base = queue.pop(0)
            if base in seen:
                continue
            seen.add(base)
            if base in facts.classes:
                if name in facts.methods.get(base, ()):
                    found.extend(summaries.get(summary_key(name, base), ()))
                    defined = True
                else:
                    queue.extend(facts.bases.get(base, ()))
            else:
                # A base in another file most likely provides the method
                # (whether or not it writes descriptions); never guess a
                # same-named method of an unrelated class instead.
                defined = True
                if external is not None:
                    found.extend(external(facts, replace(call, callee=f"{base}.{name}")))
        return found, defined

    def lookup(call: CallSite) -> List[ParamWrite]:
        name, qualifier = _last_segment(call.callee)
        if _SUPER_QUALIFIER_RE.match(qualifier) or (
            qualifier == "base." and facts.language == "c_sharp"
        ):
            # ``super().arm(t)`` / ``super.arm(t)``: the base class's method.
            if not call.enclosing_class:
                return []
            return list(dict.fromkeys(inherited(call.enclosing_class, name, call)[0]))
        instance_of = instance_class(facts, qualifier)
        if instance_of:
            # ``armer.arm(t)`` / ``Armer().arm(t)``: a method of ``Armer``.
            qualifier = instance_of + "."
            call = replace(call, callee=f"{instance_of}.{name}")
        produced = factory_classes(facts, qualifier.rstrip(".:->"))
        if produced:
            # ``newArmer().arm(t)``: a method of each class the factory may return.
            found: List[ParamWrite] = []
            for cls in produced:
                found.extend(lookup_on(replace(call, callee=f"{cls}.{name}"), name, cls + "."))
            return list(dict.fromkeys(found))
        return list(dict.fromkeys(lookup_on(call, name, qualifier)))

    def lookup_on(call: CallSite, name: str, qualifier: str) -> List[ParamWrite]:
        found: List[ParamWrite] = []
        named_class = qualifier.rstrip(".:->")
        bare_method = qualifier == "" and facts.language in _BARE_CALL_METHOD_LANGUAGES
        if qualifier in _SELF_QUALIFIERS or qualifier == "" or named_class in facts.classes:
            if qualifier in _SELF_QUALIFIERS or bare_method:
                cls = call.enclosing_class
            else:
                cls = named_class if qualifier else None
            if cls and name in facts.methods.get(cls, ()):
                found.extend(summaries.get(summary_key(name, cls), ()))
            else:
                from_bases, defined = inherited(cls, name, call) if cls else ([], False)
                found.extend(from_bases)
                if qualifier == "":
                    found.extend(summaries.get(name, ()))
                elif not defined:
                    # Method not defined on that class or its known bases:
                    # any same-named method in this file.
                    for key, writes in summaries.items():
                        if key == name or key.endswith("." + name):
                            found.extend(writes)
        if external is not None:
            found.extend(external(facts, call))
        return found

    def resolve(call: CallSite, pw: ParamWrite):
        arg = _call_argument(call, pw.param, pw.param_name)
        if arg is None:
            return None
        if pw.text_param is not None:
            text_arg = _call_argument(call, pw.text_param, pw.text_param_name)
            if text_arg is None:
                return None
            text_expr, text_value = text_arg
        else:
            text_expr, text_value = None, pw.text
        name, _ = _last_segment(call.callee)
        return arg[0], text_expr, text_value, (name, *pw.helpers)

    for _ in range(_PROPAGATION_ROUNDS):
        grew = False
        for call in facts.calls:
            if not call.enclosing:
                continue
            here = summary_key(call.enclosing, call.enclosing_class)
            for pw in lookup(call):
                if f"{facts.path}:{here}" in pw.chain:
                    continue
                resolved = resolve(call, pw)
                if resolved is None:
                    continue
                arg_text, text_expr, text_value, helpers = resolved
                arg_parts = split_target(arg_text) or [""]
                head = arg_parts[0]
                if head not in call.enclosing_params:
                    continue
                params = call.enclosing_params
                text_param = (
                    params.index(text_expr)
                    if text_value is None and text_expr in params
                    else None
                )
                new = ParamWrite(
                    param=params.index(head),
                    param_name=head,
                    text=None
                    if text_param is not None
                    else (text_value if text_value is not None else computed_text(text_expr or "")),
                    text_param=text_param,
                    text_param_name=params[text_param] if text_param is not None else None,
                    mode=pw.mode,
                    via=pw.via,
                    condition=_join_conditions(call.condition, pw.condition),
                    origin=pw.origin,
                    helpers=helpers,
                    path=".".join(p for p in (*arg_parts[1:], pw.path) if p),
                    chain=(*pw.chain, f"{facts.path}:{here}"),
                )
                bucket = summaries.setdefault(here, set())
                if new not in bucket:
                    bucket.add(new)
                    grew = True
        if not grew:
            break

    for call in facts.calls:
        for pw in lookup(call):
            resolved = resolve(call, pw)
            if resolved is None:
                continue
            arg_text, text_expr, text_value, helpers = resolved
            head = (split_target(arg_text) or [""])[0]
            if call.enclosing and head in call.enclosing_params:
                continue
            via = f"{pw.via} via " + " -> ".join(f"{h}()" for h in helpers)
            changes.append(
                DescriptionChange(
                    target=_with_path(arg_text, pw.path),
                    text=text_value if text_value is not None else computed_text(text_expr or ""),
                    mode=pw.mode,
                    via=via,
                    line=call.line,
                    condition=_join_conditions(call.condition, pw.condition),
                    file=facts.path,
                    enclosing=call.enclosing,
                    start_byte=call.start_byte,
                    cross_file=pw.origin != facts.path,
                )
            )
    return summaries, changes


# ---------------------------------------------------------------------------
# Python facts
# ---------------------------------------------------------------------------

_PY_REGISTRATION_METHODS = frozenset(
    {"tool", "prompt", "resource", "add_tool", "add_prompt", "add_resource"}
)


def _py_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (ValueError, TypeError, AttributeError, RecursionError):
        return "<expr>"


def _py_target_expr(node: ast.expr) -> Optional[str]:
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _py_unparse(node)
    return None


def py_docstring_value_text(value: ast.expr) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    try:
        literal = ast.literal_eval(value)
        if isinstance(literal, str):
            return literal
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        pass
    return computed_text(_py_unparse(value))


def _py_docstring_assignment(node: ast.AST):
    """``(target, value, mode)`` for ``x.__doc__ = v`` / ``+=`` / ``setattr``."""

    def doc_target(target: ast.expr) -> Optional[str]:
        if isinstance(target, ast.Attribute) and target.attr == "__doc__":
            return _py_target_expr(target.value)
        # ``vars(fn)["__doc__"]`` / ``fn.__dict__["__doc__"]``
        if (
            isinstance(target, ast.Subscript)
            and isinstance(target.slice, ast.Constant)
            and target.slice.value == "__doc__"
        ):
            holder = target.value
            if (
                isinstance(holder, ast.Call)
                and isinstance(holder.func, ast.Name)
                and holder.func.id == "vars"
                and len(holder.args) == 1
            ):
                return _py_target_expr(holder.args[0])
            if isinstance(holder, ast.Attribute) and holder.attr == "__dict__":
                return _py_target_expr(holder.value)
        return None

    if isinstance(node, ast.Assign):
        for target in node.targets:
            name = doc_target(target)
            if name:
                return name, node.value, "replace"
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        name = doc_target(node.target)
        if name:
            return name, node.value, "replace"
    elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
        name = doc_target(node.target)
        if name:
            return name, node.value, "append"
    elif (
        isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "setattr")
            # ``object.__setattr__(fn, "__doc__", v)``
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "__setattr__")
        )
        and len(node.args) == 3
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "__doc__"
    ):
        name = _py_target_expr(node.args[0])
        if name:
            return name, node.args[2], "replace"
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "update"
    ):
        # ``fn.__dict__.update(__doc__=v)`` / ``vars(fn).update({"__doc__": v})``
        holder = node.func.value
        name = None
        if isinstance(holder, ast.Attribute) and holder.attr == "__dict__":
            name = _py_target_expr(holder.value)
        elif (
            isinstance(holder, ast.Call)
            and isinstance(holder.func, ast.Name)
            and holder.func.id == "vars"
            and len(holder.args) == 1
        ):
            name = _py_target_expr(holder.args[0])
        if name:
            for keyword in node.keywords:
                if keyword.arg == "__doc__":
                    return name, keyword.value, "replace"
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    for key, value in zip(arg.keys, arg.values):
                        if isinstance(key, ast.Constant) and key.value == "__doc__":
                            return name, value, "replace"
    return None, None, None


def _py_description_reregistration(node: ast.AST):
    """``(target, description)`` for ``mcp.tool(description=...)(fn)`` and
    ``mcp.add_tool(fn, description=...)``."""
    if not isinstance(node, ast.Call):
        return None, None
    func = node.func
    if isinstance(func, ast.Call) and isinstance(func.func, ast.Attribute):
        registrar, fn_args = func, node.args
    elif isinstance(func, ast.Attribute):
        registrar, fn_args = node, node.args
    else:
        return None, None
    if registrar.func.attr not in _PY_REGISTRATION_METHODS or not fn_args:
        return None, None
    target = _py_target_expr(fn_args[0])
    if target is None:
        return None, None
    for keyword in registrar.keywords:
        if keyword.arg == "description":
            return target, keyword.value
    return None, None


def _py_enclosing_function(node: ast.AST, parents: Dict[ast.AST, ast.AST]):
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return cur
        cur = parents.get(cur)
    return None


def _py_enclosing_condition(
    node: ast.AST, parents: Dict[ast.AST, ast.AST]
) -> Optional[str]:
    conditions: List[str] = []
    child, cur = node, parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.If, ast.While)) and child is not cur.test:
            test = _py_unparse(cur.test)
            conditions.append(f"not ({test})" if child in cur.orelse else test)
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)):
            break
        child, cur = cur, parents.get(cur)
    return " and ".join(reversed(conditions)) or None


def _py_params(fn: ast.AST) -> Tuple[str, ...]:
    args = fn.args
    names = [a.arg for a in [*args.posonlyargs, *args.args]]
    if names and names[0] in ("self", "cls") and not isinstance(fn, ast.Lambda):
        names = names[1:]
    names.extend(a.arg for a in args.kwonlyargs)
    return tuple(names)


def _py_returned_classes(fn: ast.AST) -> List[str]:
    """Classes (or factories, resolved later) a function may return: what
    each ``return X(...)`` in its own body calls. The ``-> Armer``
    annotation only counts when the body returns something else, since
    annotations are not enforced and must not hide what the body returns."""
    returned: List[str] = []
    opaque = False
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Return) and node.value is not None:
            value = node.value
            if isinstance(value, ast.Call) and isinstance(value.func, (ast.Name, ast.Attribute)):
                name = _py_unparse(value.func)
                if name not in returned:
                    returned.append(name)
            elif not (isinstance(value, ast.Constant) and value.value is None):
                opaque = True
        stack.extend(ast.iter_child_nodes(node))
    if returned and not opaque:
        return returned
    returns = getattr(fn, "returns", None)
    if isinstance(returns, ast.Constant) and isinstance(returns.value, str):
        name = returns.value
    elif isinstance(returns, (ast.Name, ast.Attribute)):
        name = _py_unparse(returns)
    else:
        name = ""
    name = name.rsplit(".", 1)[-1]
    return returned + ([name] if name[:1].isupper() and name not in returned else [])


def factory_classes(facts: "FileFacts", name: str, _depth: int = 0) -> List[str]:
    """Classes ``name`` (a factory of this file) may return, following
    factories that return other factories."""
    out: List[str] = []
    for produced in facts.factories.get(name, ()):
        if produced in facts.factories and produced != name and _depth < 4:
            out.extend(factory_classes(facts, produced, _depth + 1))
        elif produced not in out:
            out.append(produced)
    return out


def _py_literal(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def python_imports(tree: ast.AST) -> Dict[str, Tuple[str, Optional[str]]]:
    imports: Dict[str, Tuple[str, Optional[str]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            spec = "." * node.level + (node.module or "")
            for alias in node.names:
                imports[alias.asname or alias.name] = (spec, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports[alias.asname] = (alias.name, None)
                else:
                    head = alias.name.split(".")[0]
                    imports[head] = (head, None)
    return imports


def python_description_facts(tree: ast.AST, path: str) -> FileFacts:
    facts = FileFacts(path=path, language="python", imports=python_imports(tree))
    parents: Dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def method_class(fn: Optional[ast.AST]) -> Optional[str]:
        parent = parents.get(fn) if fn is not None else None
        return parent.name if isinstance(parent, ast.ClassDef) else None

    def scope(node: ast.AST) -> Tuple[Optional[str], Tuple[str, ...]]:
        fn = _py_enclosing_function(node, parents)
        if fn is None:
            return None, ()
        return getattr(fn, "name", "<lambda>"), _py_params(fn)

    def scope_class(node: ast.AST) -> Optional[str]:
        return method_class(_py_enclosing_function(node, parents))

    # Scopes are function nodes (not names: same-named methods of different
    # classes are different scopes); ``None`` is the module.
    def fn_scope(node: ast.AST) -> Optional[ast.AST]:
        return _py_enclosing_function(node, parents)

    # Names bound in each function (parameters and assignments): there a
    # module-level alias or instance of the same name is shadowed.
    local_names: Set[Tuple[Any, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            enclosing_fn = fn_scope(node)
            if enclosing_fn is not None:
                local_names.add((enclosing_fn, node.id))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                if arg is not None:
                    local_names.add((node, arg.arg))

    def scoped(table: Dict[Tuple[Any, str], Set[str]], enclosing_fn: Any, name: str) -> Set[str]:
        """Values of ``name`` in the innermost enclosing function binding
        it (closures see their outer functions), else at module level."""
        fn = enclosing_fn
        while fn is not None:
            found = table.get((fn, name))
            if found:
                return found
            if (fn, name) in local_names:
                return set()
            fn = fn_scope(fn)
        return table.get((None, name)) or set()

    # ``alias = fn``, ``alias: T = fn`` and ``for fn in (a, b):`` bind a name
    # to other names in one scope; writes and helper arguments through it
    # reach the originals. ``h = Helper()`` / ``self.h = Helper()`` make
    # ``h.arm(...)`` a call of ``Helper.arm``.
    aliases: Dict[Tuple[Any, str], Set[str]] = {}
    instances: Dict[Tuple[Any, str], Set[str]] = {}
    for node in ast.walk(tree):
        sources: List[ast.expr] = []
        target: Optional[ast.expr] = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, sources = node.targets[0], [node.value]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, sources = node.target, [node.value]
        elif isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(
            node.iter, (ast.List, ast.Tuple, ast.Set)
        ):
            target, sources = node.target, list(node.iter.elts)
        if isinstance(target, ast.Name):
            names = {s.id for s in sources if isinstance(s, ast.Name) and s.id != target.id}
            if names:
                aliases.setdefault((fn_scope(node), target.id), set()).update(names)
        value = sources[0] if len(sources) == 1 and not isinstance(node, (ast.For, ast.AsyncFor)) else None
        # ``Armer()`` or a factory (``make_armer()`` / ``lib.make_armer()``,
        # resolved through ``facts.factories`` here or in the file defining it).
        if isinstance(value, ast.Call) and isinstance(value.func, (ast.Name, ast.Attribute)):
            built_by = _py_unparse(value.func)
            if isinstance(target, ast.Name):
                key = (fn_scope(node), target.id)
            elif (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id in ("self", "cls")
            ):
                key = (f"class {scope_class(node)}", f"self.{target.attr}")
            else:
                continue
            instances.setdefault(key, set()).add(built_by)
            if key[0] is None:
                facts.instances[key[1]] = built_by

    def resolve_alias(expr: str, enclosing: Any) -> List[str]:
        parts = expr.split(".", 1)
        heads, seen = [parts[0]], set()
        resolved: List[str] = []
        while heads:
            head = heads.pop()
            if head in seen or len(seen) > 20:
                continue
            seen.add(head)
            originals = scoped(aliases, enclosing, head)
            if originals:
                heads.extend(sorted(originals))
            else:
                resolved.append(head)
        return [".".join([h, *parts[1:]]) for h in resolved] or [expr]

    def resolve_callee(func: ast.expr, node: ast.AST) -> List[str]:
        """``h.arm`` as ``Helper.arm`` when ``h`` is a ``Helper`` here."""
        callee = _py_unparse(func)
        if not isinstance(func, ast.Attribute):
            return [callee]
        holder = func.value
        classes: Set[str] = set()
        if isinstance(holder, ast.Name):
            classes = scoped(instances, fn_scope(node), holder.id)
        elif (
            isinstance(holder, ast.Attribute)
            and isinstance(holder.value, ast.Name)
            and holder.value.id in ("self", "cls")
        ):
            classes = instances.get((f"class {scope_class(node)}", f"self.{holder.attr}"), set())
        return [f"{cls}.{func.attr}" for cls in sorted(classes)] or [callee]

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            facts.functions.setdefault(node.name, _py_params(node))
            cls = method_class(node)
            if cls:
                facts.methods.setdefault(cls, set()).add(node.name)
            elif not isinstance(parents.get(node), (ast.FunctionDef, ast.AsyncFunctionDef)):
                produced = _py_returned_classes(node)
                if produced:
                    facts.factories[node.name] = produced
            enclosing, params = scope(node)
            for dec in node.decorator_list:
                if isinstance(dec, (ast.Name, ast.Attribute)):
                    facts.calls.append(
                        CallSite(
                            callee=_py_unparse(dec),
                            args=(node.name,),
                            values=(None,),
                            kwargs=(),
                            line=dec.lineno,
                            condition=_py_enclosing_condition(node, parents),
                            enclosing=enclosing,
                            enclosing_params=params,
                            enclosing_class=scope_class(node),
                        )
                    )
        elif isinstance(node, ast.ClassDef):
            facts.classes.add(node.name)
            bases = [
                _py_unparse(base) for base in node.bases if isinstance(base, (ast.Name, ast.Attribute))
            ]
            if bases:
                facts.bases[node.name] = bases

        target, value, mode = _py_docstring_assignment(node)
        via = "__doc__ assignment"
        if target is None:
            target, value = _py_description_reregistration(node)
            mode, via = "replace", "re-registration with description"
        if target is not None:
            enclosing, params = scope(node)
            text = py_docstring_value_text(value)
            for resolved_target in resolve_alias(target, fn_scope(node)):
                facts.writes.append(
                    DescriptionWrite(
                        target=resolved_target,
                        text=text,
                        mode=mode,
                        via=via,
                        line=getattr(node, "lineno", 0),
                        condition=_py_enclosing_condition(node, parents),
                        enclosing=enclosing,
                        enclosing_params=params,
                        text_expr=computed_expr(text),
                        enclosing_class=scope_class(node),
                    )
                )
            continue

        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            enclosing, params = scope(node)
            # ``for fn in (a, b): poison(fn)`` calls ``poison`` with each.
            choices = [
                resolve_alias(arg.id, fn_scope(node)) if isinstance(arg, ast.Name) else [_py_unparse(arg)]
                for arg in node.args
            ]
            for callee in resolve_callee(node.func, node):
                for arg_texts in bounded_product(choices):
                    facts.calls.append(
                        CallSite(
                            callee=callee,
                            args=arg_texts,
                            values=tuple(_py_literal(a) for a in node.args),
                            kwargs=tuple(
                                (k.arg, _py_unparse(k.value), _py_literal(k.value))
                                for k in node.keywords
                                if k.arg
                            ),
                            line=node.lineno,
                            condition=_py_enclosing_condition(node, parents),
                            enclosing=enclosing,
                            enclosing_params=params,
                            enclosing_class=scope_class(node),
                        )
                    )
    return facts


_MAX_ALIAS_COMBINATIONS = 8


def bounded_product(choices: List[List[str]]) -> List[Tuple[str, ...]]:
    """Argument tuples for each combination of alternatives, at most
    ``_MAX_ALIAS_COMBINATIONS`` (the first alternative of each beyond that)."""
    combos: List[Tuple[str, ...]] = [()]
    for options in choices:
        combos = [(*combo, option) for combo in combos for option in options][
            :_MAX_ALIAS_COMBINATIONS
        ]
    return combos


# ---------------------------------------------------------------------------
# Import / binding scanners for tree-sitter languages
# ---------------------------------------------------------------------------

_JS_IMPORT_RE = re.compile(
    r"""import\s+(?:type\s+)?(?:(?P<default>[\w$]+)\s*,?\s*)?"""
    r"""(?:\{(?P<named>[^}]*)\}|\*\s*as\s+(?P<ns>[\w$]+))?\s*from\s*["'](?P<spec>[^"']+)["']"""
)
_JS_REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+(?:\{(?P<named>[^}]*)\}|(?P<ns>[\w$]+))\s*=\s*"""
    r"""require\(\s*["'](?P<spec>[^"']+)["']\s*\)"""
)
_GO_IMPORT_RE = re.compile(r"""^\s*(?:import\s+)?(?P<alias>[\w.]+\s+)?"(?P<spec>[^"]+)"\s*$""", re.MULTILINE)
_CLASS_RE = re.compile(r"\b(?:class|object|interface|struct|module|enum|record|trait)\s+([A-Z]\w*)")
_BOUND_RE = {
    "go": re.compile(r"(?:\bvar\s+(\w+(?:\s*,\s*\w+)*)|(\w+(?:\s*,\s*\w+)*)\s*:=|\bfunc\s+(\w+))"),
    "javascript": re.compile(r"\b(?:const|let|var|function|class)\s+([\w$]+)"),
    "typescript": re.compile(r"\b(?:const|let|var|function|class)\s+([\w$]+)"),
}


def scan_imports(language: str, source: str) -> Dict[str, Tuple[str, Optional[str]]]:
    imports: Dict[str, Tuple[str, Optional[str]]] = {}
    if language in ("javascript", "typescript"):
        for match in _JS_IMPORT_RE.finditer(source):
            spec = match.group("spec")
            if match.group("default"):
                imports[match.group("default")] = (spec, "default")
            if match.group("ns"):
                imports[match.group("ns")] = (spec, None)
            for entry in (match.group("named") or "").split(","):
                parts = entry.replace("type ", "").split(" as ")
                if parts[0].strip():
                    imports[parts[-1].strip()] = (spec, parts[0].strip())
        for match in _JS_REQUIRE_RE.finditer(source):
            spec = match.group("spec")
            if match.group("ns"):
                imports[match.group("ns")] = (spec, None)
            for entry in (match.group("named") or "").split(","):
                parts = entry.split(":")
                if parts[0].strip():
                    imports[parts[-1].strip()] = (spec, parts[0].strip())
    elif language == "go":
        for match in _GO_IMPORT_RE.finditer(source):
            spec = match.group("spec")
            alias = (match.group("alias") or "").strip() or spec.rstrip("/").split("/")[-1]
            if alias not in ("_", "."):
                imports[alias] = (spec, None)
    return imports


_JS_REEXPORT_RE = re.compile(
    r"""export\s+(?:type\s+)?\{(?P<named>[^}]*)\}\s*from\s*["'](?P<spec>[^"']+)["']"""
)
_JS_STAR_REEXPORT_RE = re.compile(
    r"""export\s+\*\s*(?:as\s+(?P<ns>[\w$]+)\s+)?from\s*["'](?P<spec>[^"']+)["']"""
)
_JS_LOCAL_EXPORT_RE = re.compile(r"""export\s*\{(?P<named>[^}]*)\}\s*(?!\s*from)(?:;|$)""", re.MULTILINE)
_JS_DEFAULT_EXPORT_RE = re.compile(
    r"""(?:export\s+default|module\.exports\s*=)\s*(?P<name>[\w$]+)\s*;?\s*$""", re.MULTILINE
)
_JS_DEFAULT_FUNCTION_RE = re.compile(
    r"""export\s+default\s+(?:async\s+)?function\s*\*?\s*(?P<name>[\w$]+)"""
)
_JS_DEFAULT_EXPRESSION_RE = re.compile(r"""(?:export\s+default|module\.exports\s*=)\s*""")
DEFAULT_EXPORT_MARKER = "<default export at line "
_JS_CJS_EXPORT_RE = re.compile(
    r"""(?:module\.)?exports\.(?P<exported>[\w$]+)\s*=\s*(?P<local>[\w$]+)\s*;?\s*$""", re.MULTILINE
)


@dataclass
class ModuleLinks:
    """How a module's exported names map to imports, re-exports and locals."""

    imports: Dict[str, Tuple[str, Optional[str]]] = field(default_factory=dict)
    reexports: Dict[str, Tuple[str, Optional[str]]] = field(default_factory=dict)
    star_specs: List[str] = field(default_factory=list)
    aliases: Dict[str, str] = field(default_factory=dict)
    default: Optional[str] = None
    default_line: Optional[int] = None


def scan_module_links(language: str, source: str) -> ModuleLinks:
    if language == "python":
        try:
            return ModuleLinks(imports=python_imports(ast.parse(source)))
        except (SyntaxError, ValueError, RecursionError):
            return ModuleLinks()
    links = ModuleLinks(imports=scan_imports(language, source))
    if language not in ("javascript", "typescript"):
        return links
    for match in _JS_REEXPORT_RE.finditer(source):
        for entry in match.group("named").split(","):
            parts = entry.replace("type ", "").split(" as ")
            if parts[0].strip():
                links.reexports[parts[-1].strip()] = (match.group("spec"), parts[0].strip())
    for match in _JS_STAR_REEXPORT_RE.finditer(source):
        if match.group("ns"):
            links.reexports[match.group("ns")] = (match.group("spec"), None)
        else:
            links.star_specs.append(match.group("spec"))
    for match in _JS_LOCAL_EXPORT_RE.finditer(source):
        for entry in match.group("named").split(","):
            parts = entry.split(" as ")
            if len(parts) == 2 and parts[0].strip():
                links.aliases[parts[1].strip()] = parts[0].strip()
    for match in _JS_CJS_EXPORT_RE.finditer(source):
        if match.group("exported") != match.group("local"):
            links.aliases[match.group("exported")] = match.group("local")
    default = _JS_DEFAULT_EXPORT_RE.search(source) or _JS_DEFAULT_FUNCTION_RE.search(source)
    if default:
        links.default = default.group("name")
    else:
        expression = _JS_DEFAULT_EXPRESSION_RE.search(source)
        if expression:
            links.default_line = source.count("\n", 0, expression.end()) + 1
    return links


def scan_bound_names(language: str, source: str) -> Set[str]:
    pattern = _BOUND_RE.get(language)
    if pattern is None:
        return set()
    return {
        name.strip()
        for m in pattern.finditer(source)
        for group in m.groups()
        if group
        for name in group.split(",")
        if name.strip()
    }


def scan_classes(source: str) -> Set[str]:
    return set(_CLASS_RE.findall(source))


_EXTENDS_RE = re.compile(
    # ``class A extends B`` (JS/TS/Java/PHP), ``class A<T>(x: T) : B()``
    # (Kotlin), ``class A : B`` (C#/Swift/Scala)
    r"\bclass\s+([A-Za-z_]\w*)\s*(?:<[^>{]*>)?\s*(?:\([^)]*\))?\s*"
    r"(?:extends\s+|:\s*)([A-Za-z_][\w.:\\]*)"
)
# ``class A < B``; only Ruby, where ``<`` cannot open generic parameters.
_RUBY_EXTENDS_RE = re.compile(r"\bclass\s+([A-Za-z_]\w*)\s*<\s*([A-Za-z_][\w:]*)")
_GO_STRUCT_RE = re.compile(r"\btype\s+([A-Za-z_]\w*)\s+struct\s*\{([^{}]*)\}")
_GO_EMBEDDED_RE = re.compile(r"^\s*\*?([A-Za-z_][\w.]*)\s*(?:`[^`]*`)?\s*(?://.*)?$", re.MULTILINE)


def scan_bases(language: str, source: str) -> Dict[str, List[str]]:
    """Class -> the classes it extends (or, in Go, the structs it embeds)."""
    bases: Dict[str, List[str]] = {}
    if language == "go":
        for match in _GO_STRUCT_RE.finditer(source):
            embedded = _GO_EMBEDDED_RE.findall(match.group(2))
            if embedded:
                bases[match.group(1)] = embedded
        return bases
    pattern = _RUBY_EXTENDS_RE if language == "ruby" else _EXTENDS_RE
    for match in pattern.finditer(source):
        base = re.sub(r"::|\\", ".", match.group(2)).strip(".")
        bases.setdefault(match.group(1), []).append(base)
    return bases


# ---------------------------------------------------------------------------
# Repository index
# ---------------------------------------------------------------------------

_DESCRIPTION_MARKER_RE = re.compile(
    rb"(?i:description)|__doc__|\bTool\s*(?:[\(\{]|::new|\.define)"
)
_JS_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")

def _norm(path: str) -> str:
    return os.path.normpath(path)


def _language_family(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in _JS_EXTS:
        return "js"
    if ext in (".kt", ".kts", ".java"):
        return "jvm"
    return ext


def _strip_js_ext(path: str) -> str:
    for ext in _JS_EXTS:
        if path.endswith(ext):
            return path[: -len(ext)]
    return path


class RuntimeDescriptionIndex:
    """Repository-wide view of tool-description changes.

    Built once per directory scan. :meth:`apply` adds to a file's tool
    contexts the changes that originate in *other* files (writes on an
    imported tool, same-package Go writes, tool objects rebuilt with a
    known tool's name) or that go through helpers defined in other files.
    Changes made entirely within one file are handled by the per-file
    extractors.
    """

    def __init__(self) -> None:
        self._files: Set[str] = set()
        self._facts: Dict[str, FileFacts] = {}
        self._summaries: Dict[str, Dict[str, Set[ParamWrite]]] = {}
        self._by_target_file: Dict[str, List[DescriptionChange]] = {}
        self._redefinitions: List[Tuple[str, str, DescriptionWrite]] = []
        self._redefinition_sources: Dict[str, str] = {}
        self._source_text: Dict[str, str] = {}
        self._sources: Dict[str, bytes] = {}
        self._links_cache: Dict[str, ModuleLinks] = {}

    # -- construction -----------------------------------------------------

    @classmethod
    def build(
        cls,
        paths: Iterable[str],
        *,
        max_file_bytes: int = 5 * 1024 * 1024,
        max_total_bytes: int = 256 * 1024 * 1024,
        read: Optional[Callable[[str], bytes]] = None,
    ) -> "RuntimeDescriptionIndex":
        index = cls()
        reader = read or _read_bytes
        sources: Dict[str, bytes] = {}
        total = 0
        over_budget = 0
        for path in paths:
            norm = _norm(path)
            index._files.add(norm)
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            if size > max_file_bytes:
                continue
            if total + size > max_total_bytes:
                over_budget += 1
                continue
            try:
                data = reader(path)
            except OSError:
                continue
            if data is None or len(data) > max_file_bytes:
                continue
            if total + len(data) > max_total_bytes:
                over_budget += 1
                continue
            total += len(data)
            sources[norm] = data
        if over_budget:
            logger.warning(
                "runtime description index reached %d bytes; %d files skipped",
                total,
                over_budget,
            )

        for path, data in sources.items():
            if _DESCRIPTION_MARKER_RE.search(data):
                index._add_facts(path, data)

        # Files calling a helper (by name, or the class defining it, or a
        # subclass of that class found in an earlier round).
        names: Set[str] = set()
        default_helper_stems: Set[str] = set()
        new_paths = list(index._facts)
        for _ in range(_HELPER_SEARCH_ROUNDS):
            for path in new_paths:
                facts = index._facts[path]
                for name in summarize(facts)[0]:
                    if name == "default":
                        default_helper_stems.add(_strip_js_ext(os.path.basename(path)))
                    elif name != "<anonymous>":
                        # ``Class.method`` keys: callers name the method on
                        # an instance (``armer.arm(...)``) or the class.
                        names.update(name.split(".")[-2:])
                for subclass, bases in facts.bases.items():
                    if any(base.split(".")[-1] in names for base in bases):
                        names.add(subclass)
            patterns = [
                rb"(?<![\w$])(?:" + b"|".join(re.escape(n.encode()) for n in sorted(names)) + rb")\b"
            ] if names else []
            if default_helper_stems:
                patterns.append(
                    rb"""["'][^"'\n]*\b(?:"""
                    + b"|".join(re.escape(s.encode()) for s in sorted(default_helper_stems))
                    + rb""")(?:\.[cm]?[jt]sx?)?["']"""
                )
            if not patterns:
                break
            call_re = re.compile(b"|".join(patterns))
            new_paths = []
            for path, data in sources.items():
                if path not in index._facts and call_re.search(data):
                    index._add_facts(path, data)
                    if path in index._facts:
                        new_paths.append(path)
            if not new_paths:
                break

        index._sources = sources
        index._propagate()
        index._sources = {}
        index._links_cache = {}
        return index

    def _add_facts(self, path: str, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        try:
            facts = file_description_facts(path, text)
        except Exception as e:  # noqa: BLE001 - one unparsable file must not drop the index
            logger.debug("runtime description facts failed for %s: %s", path, type(e).__name__)
            return
        if facts is not None:
            self._facts[path] = facts
            if facts.redefinitions:
                self._source_text[path] = text

    def _propagate(self) -> None:
        self._summaries = {path: {} for path in self._facts}
        for _ in range(_PROPAGATION_ROUNDS):
            total_before = sum(len(v) for s in self._summaries.values() for v in s.values())
            for path, facts in self._facts.items():
                self._summaries[path], _ = summarize(
                    facts, self._summaries[path], self._external_summaries
                )
            total_after = sum(len(v) for s in self._summaries.values() for v in s.values())
            if total_after == total_before:
                break

        for path, facts in self._facts.items():
            _, changes = summarize(facts, self._summaries[path], self._external_summaries)
            for change in changes:
                targets = self._retarget(facts, change.target, local=change.local_head)
                if change.alias:
                    targets += [
                        t
                        for t in self._retarget(facts, change.alias, local=change.alias_local_head)
                        if t not in targets
                    ]
                for target_file, target in targets:
                    if target_file == path and not change.cross_file:
                        continue
                    self._by_target_file.setdefault(target_file, []).append(
                        replace(change, target=target)
                    )
            for name, write in facts.redefinitions:
                if not write.registered:
                    self._redefinitions.append((path, name, write))
            if facts.redefinitions:
                self._redefinition_sources[path] = self._source_text.get(path, "")
        self._source_text.clear()

    # -- resolution -------------------------------------------------------

    def _external_summaries(
        self, facts: FileFacts, call: CallSite, _depth: int = 0
    ) -> List[ParamWrite]:
        found: List[ParamWrite] = []
        for target_file, target in self._retarget(facts, call.callee):
            if target_file == facts.path:
                continue
            parts = split_target(target) or [""]
            summaries = self._summaries.get(target_file, {})
            target_facts = self._facts.get(target_file)
            owner_is_object = False
            if len(parts) >= 2 and target_facts is not None:
                owner, method = parts[-2], parts[-1]
                produced = factory_classes(target_facts, owner)
                owner_is_object = bool(
                    produced or owner in target_facts.classes or owner in target_facts.instances
                )
                for cls in dict.fromkeys([owner, target_facts.instances.get(owner), *produced]):
                    if not cls:
                        continue
                    if cls in target_facts.classes or cls == owner:
                        found.extend(self._class_method(target_facts, cls, method))
                    elif _depth < 3:
                        # A factory returning another module's class or factory.
                        found.extend(
                            self._external_summaries(
                                target_facts, replace(call, callee=f"{cls}.{method}"), _depth + 1
                            )
                        )
            if not owner_is_object:
                # ``lib.arm(t)`` / ``util.arm(t)`` on a module or plain object.
                found.extend(summaries.get(parts[-1], ()))
        return found


    def _class_method(
        self, facts: FileFacts, cls: str, method: str, depth: int = 0
    ) -> List[ParamWrite]:
        """Summaries of ``cls.method`` in ``facts``' file, following the
        class's bases (in that file or the files they are imported from)."""
        found = list(self._summaries.get(facts.path, {}).get(f"{cls}.{method}", ()))
        if found or method in facts.methods.get(cls, ()) or depth >= 4:
            return found
        for base in facts.bases.get(cls, ()):
            if base in facts.classes:
                found.extend(self._class_method(facts, base, method, depth + 1))
                continue
            for target_file, target in self._retarget(facts, base):
                base_facts = self._facts.get(target_file)
                if target_file == facts.path or base_facts is None:
                    continue
                name = (split_target(target) or [""])[-1]
                found.extend(self._class_method(base_facts, name, method, depth + 1))
        return found

    def _retarget(
        self, facts: FileFacts, expr: str, *, local: bool = False
    ) -> List[Tuple[str, str]]:
        """Files (and the expression in their scope) that ``expr`` refers to.

        ``local``: ``expr``'s head is declared in its own scope, so it names
        nothing in another file.
        """
        parts = split_target(expr)
        if not parts:
            return []
        head, rest = parts[0], parts[1:]
        if head in facts.imports:
            hops = self._import_hops(facts.path, facts.language, facts.imports[head], rest)
            found: List[Tuple[str, str]] = []
            for path, target in hops:
                for hop in self._follow(path, facts.language, target, 1, set()):
                    if hop not in found:
                        found.append(hop)
            return found
        if facts.language == "go" and not local and head not in facts.bound_names:
            directory = os.path.dirname(facts.path)
            return [
                (f, expr)
                for f in self._facts
                if f != facts.path and f.endswith(".go") and os.path.dirname(f) == directory
            ]
        return [(facts.path, expr)]

    def _import_hops(
        self,
        path: str,
        language: str,
        binding: Tuple[str, Optional[str]],
        rest: List[str],
    ) -> List[Tuple[str, str]]:
        """One hop through an import: ``(module file, expression there)``."""
        spec, symbol = binding
        if symbol is not None:
            if language == "python" and rest:
                submodule = self._resolve_module(path, language, _py_join(spec, symbol))
                if submodule:
                    return [(f, ".".join(rest)) for f in submodule]
            files = self._resolve_module(path, language, spec)
            return [(f, ".".join([symbol, *rest])) for f in files]
        if not rest:
            if language in ("javascript", "typescript"):
                return [(f, "default") for f in self._resolve_module(path, language, spec)]
            return []
        for k in range(len(rest) - 1, -1, -1):
            module = spec if k == 0 else _module_join(language, spec, rest[:k])
            files = self._resolve_module(path, language, module)
            if files:
                return [(f, ".".join(rest[k:])) for f in files]
        return []

    def _follow(
        self,
        path: str,
        language: str,
        target: str,
        depth: int,
        seen: Set[Tuple[str, str]],
    ) -> List[Tuple[str, str]]:
        """``(path, target)`` plus where re-exports and default exports lead."""
        if (path, target) in seen:
            return []
        seen.add((path, target))
        found = [(path, target)]
        parts = split_target(target)
        if depth >= _MAX_IMPORT_HOPS or not parts:
            return found
        links = self._links(path, language)
        name, rest = parts[0], parts[1:]
        if name == "default" and not links.default and links.default_line and not rest:
            found.append((path, f"{DEFAULT_EXPORT_MARKER}{links.default_line}>"))
            return found
        if name == "default" and links.default:
            name = links.default
        if name in links.aliases:
            name = links.aliases[name]
        if name != parts[0]:
            local = ".".join([name, *rest])
            found.extend(self._follow(path, language, local, depth, seen))
            return found
        binding = links.reexports.get(name) or links.imports.get(name)
        if binding is not None:
            for hop_path, hop_target in self._import_hops(path, language, binding, rest):
                found.extend(self._follow(hop_path, language, hop_target, depth + 1, seen))
        elif links.star_specs:
            for spec in links.star_specs:
                for star_path in self._resolve_module(path, language, spec):
                    found.extend(self._follow(star_path, language, target, depth + 1, seen))
        return found

    def _links(self, path: str, language: str) -> ModuleLinks:
        links = self._links_cache.get(path)
        if links is None:
            data = self._sources.get(path)
            text = data.decode("utf-8", errors="replace") if data is not None else ""
            links = scan_module_links("python" if path.endswith((".py", ".pyw")) else language, text)
            self._links_cache[path] = links
        return links

    def _resolve_module(self, path: str, language: str, spec: str) -> List[str]:
        if language == "python":
            level = len(spec) - len(spec.lstrip("."))
            parts = [p for p in spec.lstrip(".").split(".") if p]
            if level:
                base = os.path.dirname(path)
                for _ in range(level - 1):
                    base = os.path.dirname(base)
                stem = os.path.join(base, *parts) if parts else base
                candidates = [stem + ".py", os.path.join(stem, "__init__.py")]
                return [c for c in map(_norm, candidates) if c in self._files]
            if not parts:
                return []
            suffix = os.sep + os.path.join(*parts)
            return sorted(
                f
                for f in self._files
                if f.endswith((suffix + ".py", os.path.join(suffix, "__init__.py")))
            )
        if language in ("javascript", "typescript"):
            if not spec.startswith("."):
                return []
            stem = _strip_js_ext(_norm(os.path.join(os.path.dirname(path), spec)))
            return sorted(
                f
                for f in self._files
                if f.endswith(_JS_EXTS)
                and _strip_js_ext(f) in (stem, os.path.join(stem, "index"))
            )
        if language == "go":
            segments = [s for s in spec.split("/") if s]
            if not segments:
                return []
            suffix = os.sep + os.path.join(*segments[-2:])
            last = os.sep + segments[-1]
            dirs = {os.path.dirname(f) for f in self._files if f.endswith(".go")}
            match = [d for d in dirs if d.endswith(suffix)] or [d for d in dirs if d.endswith(last)]
            return sorted(f for f in self._files if f.endswith(".go") and os.path.dirname(f) in match)
        return []

    # -- application ------------------------------------------------------

    def apply(
        self,
        path: str,
        contexts: List["FunctionContext"],
        native: Any = None,
    ) -> int:
        """Add cross-file changes to ``contexts`` (the tools of ``path``)."""
        if not contexts:
            return 0
        norm = _norm(path)
        applied = 0
        for change in self._by_target_file.get(norm, []):
            local = change.file == norm
            ctx, nested = resolve_tool_target(
                change.target,
                contexts,
                native,
                change.start_byte if local else -1,
                module_only=not local,
            )
            placement = describe_nested_write(nested) if ctx is not None else None
            if placement is None:
                continue
            mode, suffix = placement
            before = len(ctx.runtime_docstring_overrides)
            add_runtime_description_override(
                ctx,
                change.text,
                line_number=change.line,
                condition=change.condition,
                mode=mode or change.mode,
                via=change.via + suffix,
                source_file=None if local else change.file,
            )
            applied += len(ctx.runtime_docstring_overrides) - before
        family = _language_family(norm)
        reference_re = _module_reference_re(norm)
        for origin, name, write in self._redefinitions:
            if origin == norm or _language_family(origin) != family:
                continue
            if os.path.dirname(origin) != os.path.dirname(norm) and not reference_re.search(
                self._redefinition_sources.get(origin, "")
            ):
                continue
            for ctx in contexts:
                if ctx.name == name or ctx.name.endswith("." + name):
                    if write.text in (ctx.docstring or ""):
                        continue
                    before = len(ctx.runtime_docstring_overrides)
                    add_runtime_description_override(
                        ctx,
                        write.text,
                        line_number=write.line,
                        condition=write.condition,
                        mode="replace",
                        via=(
                            "registration of the same tool in another file"
                            if write.in_registration
                            else "tool redefinition"
                        ),
                        source_file=origin,
                    )
                    applied += len(ctx.runtime_docstring_overrides) - before
        return applied


def _module_reference_re(path: str) -> "re.Pattern[str]":
    """Matches an import of ``path``'s module from another file.

    Go imports packages by directory; other languages name the file (or the
    class it declares) in an import / require / use line.
    """
    if path.endswith(".go"):
        directory = os.path.basename(os.path.dirname(path))
        return re.compile(r'"[^"\n]*/' + re.escape(directory) + r'"')
    if _language_family(path) == "js":
        stem = os.path.basename(_strip_js_ext(path))
        if stem == "index":
            stem = os.path.basename(os.path.dirname(path))
        return re.compile(
            r"""["']\.{1,2}/(?:[^"'\n]*/)?"""
            + re.escape(stem)
            + r"""(?:/index)?(?:\.[cm]?[jt]sx?)?["']"""
        )
    word = r"(?<![\w$])" + re.escape(os.path.splitext(os.path.basename(path))[0]) + r"(?![\w$])"
    return re.compile(
        r"(?m)(?:^\s*(?:import|from|use|using|include|require(?:_once)?|mod)\b[^\n]*"
        r"""|\bfrom\s*["'][^"'\n]*|\brequire(?:_relative)?\s*\(?\s*["'][^"'\n]*)"""
        + word
    )


def _module_join(language: str, spec: str, parts: List[str]) -> str:
    if language == "python":
        return _py_join(spec, ".".join(parts))
    return spec.rstrip("/") + "/" + "/".join(parts)


def _py_join(spec: str, name: str) -> str:
    return spec + name if spec.endswith(".") else f"{spec}.{name}"


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def file_description_facts(path: str, source: str) -> Optional[FileFacts]:
    """Facts for one file, or ``None`` when its language is unsupported."""
    from .native_analyzer import NativeAnalyzer

    try:
        if path.endswith((".py", ".pyw")):
            return python_description_facts(ast.parse(source), path)
        analyzer = NativeAnalyzer(source, path)
        root = analyzer._ts_parse_root()
        if root is None:
            return None
        return analyzer._ts_description_facts(root)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        logger.debug("runtime description facts skipped for %s: %s", path, type(e).__name__)
        return None


def resolve_tool_target(
    target: str,
    contexts: List["FunctionContext"],
    native: Any = None,
    start_byte: int = -1,
    *,
    module_only: bool = False,
) -> Tuple[Optional["FunctionContext"], Optional[str]]:
    """``(tool, nested path)`` for ``target``, an expression in the file's scope.

    ``nested path`` is set when ``target`` is a field inside the tool
    (``tool.inputSchema.properties.q``) rather than the tool itself.
    ``module_only`` (a change made in another file) resolves only names
    visible to other files, not locals of this file's functions.
    """
    reg_contexts = getattr(native, "_last_reg_contexts", None)
    if target.startswith(DEFAULT_EXPORT_MARKER):
        line = int(target[len(DEFAULT_EXPORT_MARKER) : -1])
        for reg, ctx in reg_contexts or ():
            call_node = reg.get("call_node")
            if call_node is not None and call_node.start_point[0] + 1 == line:
                return ctx, None
        return None, None
    parts = split_target(target)
    if native is not None and reg_contexts is not None:
        ctx, nested = native._ts_resolve_receiver(
            target, contexts, reg_contexts, start_byte, module_only=module_only
        )
        if ctx is None and len(parts) == 1:
            # The handler's source symbol when the tool is registered under
            # another name (annotation tools, ``definition_name``).
            ctx = next(
                (c for c in contexts if getattr(c, "definition_name", None) == parts[0]), None
            )
        return ctx, nested
    if not parts:
        return None, None
    head = parts[0].lstrip("$")
    nested = ".".join(parts[1:]) or None
    for ctx in contexts:
        if head in (ctx.name, getattr(ctx, "definition_name", None)):
            return ctx, nested
    for ctx in contexts:
        if ctx.name.endswith("." + head):
            return ctx, nested
    return None, None
