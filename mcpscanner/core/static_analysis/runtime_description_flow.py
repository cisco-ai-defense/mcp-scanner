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

_PROPAGATION_ROUNDS = 6
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

    ``mode`` is ``"replace"`` or ``"append"``; ``via`` names the mechanism
    (``"__doc__ assignment"``, ``"description field write"``, ...).
    ``source_file`` is set when the change is made in another file.
    """
    text = (text or "")[:MAX_RUNTIME_DESCRIPTION_CHARS]
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
    where = f"line {line_number}, {via}"
    if source_file:
        override["source_file"] = source_file
        where = f"{os.path.basename(source_file)} {where}"
    ctx.runtime_docstring_overrides.append(override)
    if condition:
        where += f", when `{condition}`"
    verb = "extended" if mode == "append" else "replaced"
    ctx.docstring = (
        f"{ctx.docstring or ''}\n\n"
        f"[Runtime description override ({where}): the tool description "
        f"an agent receives is {verb} at runtime with the text below]\n"
        f"{text}"
    ).lstrip()


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


_LOCAL_QUALIFIERS = {"", "this.", "self.", "cls.", "$this->", "self::", "static::", "Self::", "@"}

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
        head = (split_target(write.target) or [""])[0]
        params = write.enclosing_params
        if write.enclosing and head in params:
            text_param = (
                params.index(write.text_expr)
                if write.text_expr and write.text_expr in params
                else None
            )
            summaries.setdefault(write.enclosing, set()).add(
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
                )
            )

    def lookup(call: CallSite) -> List[ParamWrite]:
        name, qualifier = _last_segment(call.callee)
        found: List[ParamWrite] = []
        if qualifier in _LOCAL_QUALIFIERS or qualifier.rstrip(".:->") in facts.classes:
            found.extend(summaries.get(name, ()))
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
        if name in pw.helpers:
            return None
        return arg[0], text_expr, text_value, (name, *pw.helpers)

    for _ in range(_PROPAGATION_ROUNDS):
        grew = False
        for call in facts.calls:
            if not call.enclosing:
                continue
            for pw in lookup(call):
                resolved = resolve(call, pw)
                if resolved is None:
                    continue
                arg_text, text_expr, text_value, helpers = resolved
                head = (split_target(arg_text) or [""])[0]
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
                )
                bucket = summaries.setdefault(call.enclosing, set())
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
                    target=arg_text,
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
        and isinstance(node.func, ast.Name)
        and node.func.id == "setattr"
        and len(node.args) == 3
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "__doc__"
    ):
        name = _py_target_expr(node.args[0])
        if name:
            return name, node.args[2], "replace"
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
    child, cur = node, parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.If, ast.While)):
            test = _py_unparse(cur.test)
            return f"not ({test})" if child in cur.orelse else test
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)):
            return None
        child, cur = cur, parents.get(cur)
    return None


def _py_params(fn: ast.AST) -> Tuple[str, ...]:
    args = fn.args
    names = [a.arg for a in [*args.posonlyargs, *args.args]]
    if names and names[0] in ("self", "cls") and not isinstance(fn, ast.Lambda):
        names = names[1:]
    names.extend(a.arg for a in args.kwonlyargs)
    return tuple(names)


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

    def scope(node: ast.AST) -> Tuple[Optional[str], Tuple[str, ...]]:
        fn = _py_enclosing_function(node, parents)
        if fn is None:
            return None, ()
        return getattr(fn, "name", "<lambda>"), _py_params(fn)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            facts.functions.setdefault(node.name, _py_params(node))
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
                        )
                    )
        elif isinstance(node, ast.ClassDef):
            facts.classes.add(node.name)

        target, value, mode = _py_docstring_assignment(node)
        via = "__doc__ assignment"
        if target is None:
            target, value = _py_description_reregistration(node)
            mode, via = "replace", "re-registration with description"
        if target is not None:
            enclosing, params = scope(node)
            text = py_docstring_value_text(value)
            facts.writes.append(
                DescriptionWrite(
                    target=target,
                    text=text,
                    mode=mode,
                    via=via,
                    line=getattr(node, "lineno", 0),
                    condition=_py_enclosing_condition(node, parents),
                    enclosing=enclosing,
                    enclosing_params=params,
                    text_expr=computed_expr(text),
                )
            )
            continue

        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            enclosing, params = scope(node)
            facts.calls.append(
                CallSite(
                    callee=_py_unparse(node.func),
                    args=tuple(_py_unparse(a) for a in node.args),
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
                )
            )
    return facts


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
    "go": re.compile(r"(?:\bvar\s+(\w+)|(\w+)(?:\s*,\s*\w+)*\s*:=|\bfunc\s+(\w+))"),
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
    return {name for m in pattern.finditer(source) for name in m.groups() if name}


def scan_classes(source: str) -> Set[str]:
    return set(_CLASS_RE.findall(source))


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
        read: Optional[Callable[[str], bytes]] = None,
    ) -> "RuntimeDescriptionIndex":
        index = cls()
        reader = read or _read_bytes
        sources: Dict[str, bytes] = {}
        for path in paths:
            norm = _norm(path)
            index._files.add(norm)
            try:
                data = reader(path)
            except OSError:
                continue
            if data is not None and len(data) <= max_file_bytes:
                sources[norm] = data

        for path, data in sources.items():
            if _DESCRIPTION_MARKER_RE.search(data):
                index._add_facts(path, data)

        helper_names: Set[str] = set()
        default_helper_stems: Set[str] = set()
        for path in list(index._facts):
            for name in summarize(index._facts[path])[0]:
                if name == "default":
                    default_helper_stems.add(_strip_js_ext(os.path.basename(path)))
                elif name != "<anonymous>":
                    helper_names.add(name)
        patterns = [
            rb"(?<![\w$])(?:" + b"|".join(re.escape(n.encode()) for n in sorted(helper_names)) + rb")\b"
        ] if helper_names else []
        if default_helper_stems:
            patterns.append(
                rb"""["'][^"'\n]*\b(?:"""
                + b"|".join(re.escape(s.encode()) for s in sorted(default_helper_stems))
                + rb""")(?:\.[cm]?[jt]sx?)?["']"""
            )
        if patterns:
            call_re = re.compile(b"|".join(patterns))
            for path, data in sources.items():
                if path not in index._facts and call_re.search(data):
                    index._add_facts(path, data)

        index._sources = sources
        index._propagate()
        index._sources = {}
        index._links_cache = {}
        return index

    def _add_facts(self, path: str, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        facts = file_description_facts(path, text)
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
                for target_file, target in self._retarget(facts, change.target):
                    if target_file == path and not change.cross_file:
                        continue
                    self._by_target_file.setdefault(target_file, []).append(
                        replace(change, target=target)
                    )
            for name, write in facts.redefinitions:
                self._redefinitions.append((path, name, write))
            if facts.redefinitions:
                self._redefinition_sources[path] = self._source_text.get(path, "")
        self._source_text.clear()

    # -- resolution -------------------------------------------------------

    def _external_summaries(self, facts: FileFacts, call: CallSite) -> List[ParamWrite]:
        found: List[ParamWrite] = []
        for target_file, target in self._retarget(facts, call.callee):
            if target_file == facts.path:
                continue
            name = (split_target(target) or [""])[-1]
            found.extend(self._summaries.get(target_file, {}).get(name, ()))
        return found

    def _retarget(self, facts: FileFacts, expr: str) -> List[Tuple[str, str]]:
        """Files (and the expression in their scope) that ``expr`` refers to."""
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
        if facts.language == "go" and head not in facts.bound_names:
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
            ctx = resolve_tool_target(change.target, contexts, native)
            if ctx is None:
                continue
            before = len(ctx.runtime_docstring_overrides)
            add_runtime_description_override(
                ctx,
                change.text,
                line_number=change.line,
                condition=change.condition,
                mode=change.mode,
                via=change.via,
                source_file=None if change.file == norm else change.file,
            )
            applied += len(ctx.runtime_docstring_overrides) - before
        family = _language_family(norm)
        stem_re = re.compile(
            r"(?<![\w$])" + re.escape(os.path.splitext(os.path.basename(norm))[0]) + r"(?![\w$])"
        )
        for origin, name, write in self._redefinitions:
            if origin == norm or _language_family(origin) != family:
                continue
            if os.path.dirname(origin) != os.path.dirname(norm) and not stem_re.search(
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
                        via="tool redefinition",
                        source_file=origin,
                    )
                    applied += len(ctx.runtime_docstring_overrides) - before
        return applied


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
    except (SyntaxError, ValueError, RecursionError) as e:
        logger.debug("runtime description facts skipped for %s: %s", path, type(e).__name__)
        return None


def resolve_tool_target(
    target: str,
    contexts: List["FunctionContext"],
    native: Any = None,
) -> Optional["FunctionContext"]:
    """The tool context ``target`` (an expression in the file's scope) names."""
    reg_contexts = getattr(native, "_last_reg_contexts", None)
    if target.startswith(DEFAULT_EXPORT_MARKER):
        line = int(target[len(DEFAULT_EXPORT_MARKER) : -1])
        for reg, ctx in reg_contexts or ():
            call_node = reg.get("call_node")
            if call_node is not None and call_node.start_point[0] + 1 == line:
                return ctx
        return None
    if native is not None and reg_contexts is not None:
        ctx = native._ts_tool_for_receiver(target, contexts, reg_contexts)
        if ctx is not None:
            return ctx
    parts = split_target(target)
    if not parts:
        return None
    head = parts[0].lstrip("$")
    for ctx in contexts:
        if head in (ctx.name, getattr(ctx, "definition_name", None)):
            return ctx
    for ctx in contexts:
        if ctx.name.endswith("." + head):
            return ctx
    return None
