# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""IDE-grade semantic dispatch: hierarchy, points-to, const prop, virtual targets."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from tree_sitter import Node, Parser

from ..parser.treesitter_parser import _get_language
from ..semantic.treesitter_analyzer import TreeSitterSemanticAnalyzer
from ..semantic.type_analyzer import TypeAnalyzer
from .models import Provenance

def _function_body_node(func: Node) -> Node | None:
    return (
        func.child_by_field_name("body")
        or func.child_by_field_name("body_statement")
        or func.child_by_field_name("compound_statement")
    )


def _class_name_node(class_node: Node) -> Node | None:
    return (
        class_node.child_by_field_name("name")
        or class_node.child_by_field_name("constant")
        or class_node.child_by_field_name("type")
    )


def _record_call_binding(
    bindings: list[CallSiteBinding],
    *,
    target_var: str,
    callee_name: str,
) -> None:
    bindings.append(CallSiteBinding(target_var=target_var, callee_name=callee_name))


def _treesitter_var_name(node: Node, source_bytes: bytes) -> str | None:
    if node.type == "identifier":
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")
    if node.type == "variable_name":
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")
    name = node.child_by_field_name("name")
    if name is not None:
        return source_bytes[name.start_byte : name.end_byte].decode("utf-8")
    return None


def _class_from_ruby_new_call(node: Node, source_bytes: bytes) -> str | None:
    if node.type not in _TS_CALL_TYPES:
        return None
    receiver = node.child_by_field_name("receiver")
    method = node.child_by_field_name("method")
    if receiver is None or method is None:
        return None
    meth = source_bytes[method.start_byte : method.end_byte].decode("utf-8")
    if meth != "new":
        return None
    if receiver.type == "constant":
        return source_bytes[receiver.start_byte : receiver.end_byte].decode("utf-8")
    return None


def _class_from_new_node(node: Node, source_bytes: bytes) -> str | None:
    if node.type not in ("new_expression", "object_creation_expression"):
        return None
    ctor = (
        node.child_by_field_name("constructor")
        or node.child_by_field_name("type")
        or node.child_by_field_name("name")
    )
    if ctor is None:
        for part in node.children:
            if part.type == "name":
                return source_bytes[part.start_byte : part.end_byte].decode("utf-8")
            if part.type in ("identifier", "type_identifier"):
                return source_bytes[part.start_byte : part.end_byte].decode("utf-8").split(".")[-1]
        return None
    return source_bytes[ctor.start_byte : ctor.end_byte].decode("utf-8").split(".")[-1]


_GETATTR_VAR_NAME_RE = re.compile(r"getattr\(\s*[\w$]+\s*,\s*([\w$]+)\s*\)?")
_SEND_VAR_NAME_RE = re.compile(r"\.send\(([\w$]+)\)")
_PHP_VAR_METHOD_NAME_RE = re.compile(r"->\$(\w+)$")

_TS_FUNC_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "method_declaration",
        "method",
        "singleton_method",
        "function_definition",
        "function_item",
    }
)

_TS_CLASS_TYPES = frozenset(
    {
        "class_declaration",
        "class",
        "struct_item",
        "impl_item",
        "object_declaration",
    }
)


@dataclass(frozen=True)
class DispatchTarget:
    node_id: str
    confidence: float
    context: str


@dataclass
class DispatchResult:
    targets: list[DispatchTarget] = field(default_factory=list)

    @property
    def provenance(self) -> Provenance:
        if not self.targets:
            return Provenance.AMBIGUOUS
        if len(self.targets) == 1 and self.targets[0].confidence >= 0.95:
            return Provenance.EXTRACTED
        if all(t.confidence >= 0.85 for t in self.targets):
            return Provenance.INFERRED
        return Provenance.AMBIGUOUS

    def primary(self) -> DispatchTarget | None:
        if not self.targets:
            return None
        return max(self.targets, key=lambda t: t.confidence)


@dataclass
class TypeHierarchy:
    """Class/interface inheritance within a compilation unit."""

    bases: dict[str, list[str]] = field(default_factory=dict)
    methods: dict[str, set[str]] = field(default_factory=dict)

    def all_bases(self, class_name: str) -> set[str]:
        seen: set[str] = set()
        stack = list(self.bases.get(class_name, []))
        while stack:
            base = stack.pop()
            if base in seen:
                continue
            seen.add(base)
            stack.extend(self.bases.get(base, []))
        return seen

    def all_subtypes(self, class_name: str) -> set[str]:
        children: dict[str, set[str]] = defaultdict(set)
        for child, parents in self.bases.items():
            for parent in parents:
                children[parent].add(child)
        seen: set[str] = set()
        stack = list(children.get(class_name, []))
        while stack:
            sub = stack.pop()
            if sub in seen:
                continue
            seen.add(sub)
            stack.extend(children.get(sub, []))
        return seen

    def resolve_virtual(self, static_type: str, method: str) -> set[str]:
        """Return concrete class names that may implement ``method``."""
        candidates = {static_type} | self.all_subtypes(static_type) | self.all_bases(static_type)
        out: set[str] = set()
        for cls in candidates:
            methods = self.methods.get(cls, set())
            if method in methods or not methods:
                out.add(cls)
        return out or {static_type}


@dataclass
class FunctionSemanticState:
    """Per-function points-to, alias, and constant facts."""

    instance_classes: dict[str, set[str]] = field(default_factory=dict)
    aliases: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    string_consts: dict[str, str] = field(default_factory=dict)

    def union_alias(self, left: str, right: str) -> None:
        self.aliases[left].add(right)
        self.aliases[right].add(left)

    def classes_for(self, var: str, seed: dict[str, str]) -> set[str]:
        seen_vars: set[str] = set()
        stack = [var]
        classes: set[str] = set()
        while stack:
            name = stack.pop()
            if name in seen_vars:
                continue
            seen_vars.add(name)
            if name in seed:
                classes.add(seed[name])
            classes.update(self.instance_classes.get(name, set()))
            stack.extend(self.aliases.get(name, ()))
        return classes


def build_python_hierarchy(source: str) -> TypeHierarchy:
    hierarchy = TypeHierarchy()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return hierarchy
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
        hierarchy.bases[node.name] = bases
        methods: set[str] = set()
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.add(item.name)
        hierarchy.methods[node.name] = methods
    return hierarchy


def build_treesitter_hierarchy(language: str, root: Node, source_bytes: bytes) -> TypeHierarchy:
    hierarchy = TypeHierarchy()

    def text(node: Node) -> str:
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")

    def visit(node: Node, current_class: str | None = None) -> None:
        if node.type in ("class_declaration", "class"):
            name_node = node.child_by_field_name("name")
            if name_node is None:
                return
            class_name = text(name_node)
            bases: list[str] = []
            for child in node.children:
                if child.type in ("class_heritage", "extends_clause", "superclass"):
                    for part in child.children:
                        if part.type in ("identifier", "type_identifier", "nested_type_identifier"):
                            bases.append(text(part).split(".")[-1])
                if child.type == "implements_clause":
                    for part in child.children:
                        if part.type in ("type_identifier", "identifier"):
                            iface = text(part).split(".")[-1]
                            hierarchy.bases.setdefault(class_name, []).append(iface)
            if bases:
                hierarchy.bases.setdefault(class_name, []).extend(bases)
            methods: set[str] = set()
            body = node.child_by_field_name("body")
            if body:
                for item in body.children:
                    if item.type in ("method_definition", "method_declaration"):
                        m = item.child_by_field_name("name")
                        if m:
                            methods.add(text(m))
            hierarchy.methods[class_name] = methods
            if body:
                for child in body.children:
                    visit(child, class_name)
            return
        for child in node.children:
            visit(child, current_class)

    visit(root)
    return hierarchy


def _python_function_state(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    seed_instances: dict[str, str],
) -> FunctionSemanticState:
    state = FunctionSemanticState()
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id
                if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                    state.instance_classes.setdefault(name, set()).add(node.value.func.id)
                elif isinstance(node.value, ast.IfExp):
                    for branch in (node.value.body, node.value.orelse):
                        if isinstance(branch, ast.Call) and isinstance(branch.func, ast.Name):
                            state.instance_classes.setdefault(name, set()).add(branch.func.id)
                elif isinstance(node.value, ast.Name):
                    state.union_alias(name, node.value.id)
                elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    state.string_consts[name] = node.value.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            if node.value and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                state.instance_classes.setdefault(name, set()).add(node.value.func.id)
            elif node.value and isinstance(node.value, ast.Name):
                state.union_alias(name, node.value.id)
            elif node.value and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                state.string_consts[name] = node.value.value
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                state.string_consts[node.target.id] = node.value.value
    for var, cls in seed_instances.items():
        state.instance_classes.setdefault(var, set()).add(cls)
    return state


def _treesitter_function_state(
    func: Node,
    source_bytes: bytes,
    *,
    seed_instances: dict[str, str],
) -> FunctionSemanticState:
    state = FunctionSemanticState()

    def text(node: Node) -> str:
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")

    def walk(node: Node) -> None:
        if node.type in ("lexical_declaration", "variable_declaration"):
            for child in node.children:
                if child.type != "variable_declarator":
                    continue
                name_node = child.child_by_field_name("name")
                value = child.child_by_field_name("value")
                if name_node is None or value is None:
                    continue
                name = text(name_node)
                if value.type == "new_expression":
                    ctor = value.child_by_field_name("constructor")
                    if ctor is None:
                        for part in value.children:
                            if part.type in ("identifier", "type_identifier"):
                                ctor = part
                                break
                    if ctor:
                        state.instance_classes.setdefault(name, set()).add(text(ctor))
                elif value.type == "ternary_expression":
                    for part in value.children:
                        if part.type == "new_expression":
                            ctor = part.child_by_field_name("constructor")
                            if ctor is None:
                                for child in part.children:
                                    if child.type in ("identifier", "type_identifier"):
                                        ctor = child
                                        break
                            if ctor:
                                state.instance_classes.setdefault(name, set()).add(text(ctor))
                elif value.type == "identifier":
                    state.union_alias(name, text(value))
                elif value.type == "string":
                    lit = text(value).strip("'\"")
                    state.string_consts[name] = lit
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            left_name = _treesitter_var_name(left, source_bytes) if left else None
            if left_name and right is not None:
                cls = _class_from_new_node(right, source_bytes)
                if cls:
                    state.instance_classes.setdefault(left_name, set()).add(cls)
                elif right.type in _TS_CALL_TYPES:
                    callee = _treesitter_call_name(right, source_bytes)
                    if callee and callee[0].isupper():
                        state.instance_classes.setdefault(left_name, set()).add(callee)
                elif right.type == "string":
                    state.string_consts[left_name] = text(right).strip("'\"")
                elif right.type == "identifier":
                    state.union_alias(left_name, text(right))
        elif node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            left_name = _treesitter_var_name(left, source_bytes) if left else None
            if left_name and right is not None:
                if right.type == "string":
                    state.string_consts[left_name] = text(right).strip("'\"")
                elif right.type in _TS_CALL_TYPES:
                    cls = _class_from_ruby_new_call(right, source_bytes)
                    if cls:
                        state.instance_classes.setdefault(left_name, set()).add(cls)
                    else:
                        callee = _treesitter_call_name(right, source_bytes)
                        if callee and callee[0].isupper():
                            state.instance_classes.setdefault(left_name, set()).add(callee)
        for child in node.children:
            walk(child)

    body = _function_body_node(func)
    if body:
        walk(body)
    for var, cls in seed_instances.items():
        state.instance_classes.setdefault(var, set()).add(cls)
    return state


def _match_qualified_methods(
    qualified_names: set[str],
    known_functions: set[str],
    caller_file: str,
) -> list[str]:
    matches: list[str] = []
    for qualified in qualified_names:
        short = qualified.split(".")[-1]
        for fn in known_functions:
            label = fn.split("::", 1)[-1]
            if label == qualified or label.endswith(f".{short}"):
                if fn.startswith(f"{caller_file}::") or len(matches) == 0:
                    matches.append(fn)
    deduped: list[str] = []
    seen: set[str] = set()
    for fn in matches:
        if fn not in seen:
            seen.add(fn)
            deduped.append(fn)
    return deduped


def _confidence_for_target(count: int, *, literal_method: bool, virtual: bool) -> float:
    if count == 1:
        if literal_method:
            return 1.0
        if virtual:
            return 0.9
        return 0.85
    return max(0.45, 0.85 / count)


class SemanticDispatchEngine:
    """Resolve dynamic and virtual call sites using lightweight semantic facts."""

    def __init__(
        self,
        *,
        language: str,
        source: str,
        known_functions: set[str],
        caller_file: str,
        hierarchy: TypeHierarchy,
        seed_instances: dict[str, str],
        semantic: TypeAnalyzer | TreeSitterSemanticAnalyzer | None = None,
        program_facts: ProgramFacts | None = None,
        caller_node_id: str | None = None,
    ) -> None:
        self.language = language
        self.source = source
        self.known_functions = known_functions
        self.caller_file = caller_file
        self.hierarchy = hierarchy
        self.seed_instances = seed_instances
        self.semantic = semantic
        self.program_facts = program_facts
        self.caller_node_id = caller_node_id

    @classmethod
    def for_file(
        cls,
        *,
        language: str,
        source: str,
        known_functions: set[str],
        caller_file: str,
        semantic: TypeAnalyzer | TreeSitterSemanticAnalyzer | None = None,
        program_facts: ProgramFacts | None = None,
        caller_node_id: str | None = None,
    ) -> SemanticDispatchEngine:
        seed = semantic.instance_to_class.copy() if semantic else {}
        if language == "python":
            hierarchy = build_python_hierarchy(source)
        else:
            lang = _get_language(language)
            hierarchy = TypeHierarchy()
            if lang is not None:
                root = Parser(lang).parse(source.encode("utf-8")).root_node
                hierarchy = build_treesitter_hierarchy(language, root, source.encode("utf-8"))
        return cls(
            language=language,
            source=source,
            known_functions=known_functions,
            caller_file=caller_file,
            hierarchy=hierarchy,
            seed_instances=seed,
            semantic=semantic,
            program_facts=program_facts,
            caller_node_id=caller_node_id,
        )

    def resolve(
        self,
        *,
        caller_label: str,
        callee_label: str,
        receiver: str | None,
        method: str | None,
        kind: str,
    ) -> DispatchResult:
        state = self._function_state(caller_label)
        if state is None:
            return DispatchResult()

        if receiver and method:
            return self._resolve_static_receiver(state, receiver, method, kind)

        if receiver and method is None:
            method_name = self._resolve_method_name(state, receiver, callee_label, kind)
            if method_name:
                return self._resolve_static_receiver(
                    state, receiver, method_name, kind, from_const=True
                )
            return self._resolve_bounded_receiver(state, receiver, kind)

        return DispatchResult()

    def resolve_virtual_method(
        self,
        *,
        caller_label: str,
        callee_label: str,
    ) -> DispatchResult:
        if "." not in callee_label:
            return DispatchResult()
        receiver, method = callee_label.split(".", 1)
        state = self._function_state(caller_label)
        if state is None:
            return DispatchResult()
        return self._resolve_static_receiver(state, receiver, method, "virtual", virtual=True)

    def _function_state(self, caller_label: str) -> FunctionSemanticState | None:
        if self.language == "python":
            try:
                tree = ast.parse(self.source)
            except SyntaxError:
                return None
            func = _find_python_function(tree, caller_label)
            if func is None:
                return None
            state = _python_function_state(func, seed_instances=self.seed_instances)

        else:
            lang = _get_language(self.language)
            if lang is None:
                return None
            source_bytes = self.source.encode("utf-8")
            root = Parser(lang).parse(source_bytes).root_node
            func = _find_treesitter_function(root, caller_label, source_bytes)
            if func is None:
                return None
            state = _treesitter_function_state(func, source_bytes, seed_instances=self.seed_instances)

        if self.program_facts and self.caller_node_id:
            self.program_facts.merge_into_state(self.caller_node_id, state)
        return state

    def _resolve_method_name(
        self,
        state: FunctionSemanticState,
        receiver: str,
        callee_label: str,
        kind: str,
    ) -> str | None:
        if kind == "bracket_variable":
            key = callee_label.split("[", 1)[1].rstrip("]").strip()
            if key in state.string_consts:
                return state.string_consts[key]
        if kind == "getattr_variable":
            match = _GETATTR_VAR_NAME_RE.search(callee_label)
            if match and match.group(1) in state.string_consts:
                return state.string_consts[match.group(1)]
        if kind == "send_variable":
            match = _SEND_VAR_NAME_RE.search(callee_label)
            if match and match.group(1) in state.string_consts:
                return state.string_consts[match.group(1)]
        if kind == "php_variable_method":
            match = _PHP_VAR_METHOD_NAME_RE.search(callee_label)
            if match:
                var = match.group(1)
                if var in state.string_consts:
                    return state.string_consts[var]
                if f"${var}" in state.string_consts:
                    return state.string_consts[f"${var}"]
        return None

    def _resolve_static_receiver(
        self,
        state: FunctionSemanticState,
        receiver: str,
        method: str,
        kind: str,
        *,
        from_const: bool = False,
        virtual: bool = False,
    ) -> DispatchResult:
        classes = state.classes_for(receiver, self.seed_instances)
        if not classes and self.semantic:
            cls = self.semantic.instance_to_class.get(receiver)
            if cls:
                classes = {cls}
        if not classes:
            return DispatchResult()

        qualified: set[str] = set()
        for cls in classes:
            if virtual:
                for subtype in self.hierarchy.resolve_virtual(cls, method):
                    qualified.add(f"{subtype}.{method}")
            else:
                qualified.add(f"{cls}.{method}")

        matches = _match_qualified_methods(qualified, self.known_functions, self.caller_file)
        if not matches:
            return DispatchResult()

        ctx_prefix = "virtual_dispatch" if virtual else f"semantic_{kind}"
        if from_const:
            ctx_prefix = "const_prop_" + ctx_prefix
        conf = _confidence_for_target(len(matches), literal_method=not virtual, virtual=virtual)
        targets = [
            DispatchTarget(
                node_id=fn,
                confidence=conf,
                context=f"{ctx_prefix}:{method}" if len(matches) == 1 else f"{ctx_prefix}_multi:{len(matches)}",
            )
            for fn in matches
        ]
        return DispatchResult(targets=targets)

    def _resolve_bounded_receiver(
        self,
        state: FunctionSemanticState,
        receiver: str,
        kind: str,
    ) -> DispatchResult:
        classes = state.classes_for(receiver, self.seed_instances)
        if not classes:
            return DispatchResult()
        matches: list[str] = []
        for cls in classes:
            prefix = f"{cls}."
            matches.extend(
                fn
                for fn in self.known_functions
                if fn.split("::", 1)[-1].startswith(prefix)
            )
        if not matches:
            return DispatchResult()
        conf = _confidence_for_target(len(matches), literal_method=False, virtual=False)
        return DispatchResult(
            targets=[
                DispatchTarget(
                    node_id=fn,
                    confidence=conf,
                    context=f"dynamic_dispatch_bounded:{','.join(sorted(classes))}",
                )
                for fn in matches
            ]
        )


def _find_python_function(tree: ast.Module, label: str) -> ast.FunctionDef | None:
    if "." in label:
        class_name, method_name = label.rsplit(".", 1)
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if item.name == method_name:
                            return item
        return None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == label:
            return node
    return None


def _find_treesitter_function(root: Node, label: str, source_bytes: bytes) -> Node | None:
    def text(node: Node) -> str:
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")

    if "." in label:
        class_name, method_name = label.rsplit(".", 1)
        stack = [root]
        class_node = None
        while stack:
            node = stack.pop()
            if node.type in _TS_CLASS_TYPES:
                name_node = _class_name_node(node)
                if name_node and text(name_node) == class_name:
                    class_node = node
                    break
            stack.extend(node.children)
        if class_node is None:
            return None
        body = _function_body_node(class_node)
        search_root = body if body is not None else class_node
        stack = [search_root]
        while stack:
            node = stack.pop()
            if node.type in _TS_FUNC_TYPES:
                name_node = node.child_by_field_name("name")
                if name_node and text(name_node) == method_name:
                    return node
            stack.extend(node.children)
        return None

    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in _TS_FUNC_TYPES:
            name_node = node.child_by_field_name("name")
            if name_node and text(name_node) == label:
                return node
        stack.extend(node.children)
    return None


@dataclass
class CallSiteBinding:
    target_var: str
    callee_name: str


@dataclass
class FunctionSummary:
    node_id: str
    instance_classes: dict[str, set[str]] = field(default_factory=dict)
    string_consts: dict[str, str] = field(default_factory=dict)
    return_classes: set[str] = field(default_factory=set)
    return_strings: set[str] = field(default_factory=set)
    call_bindings: list[CallSiteBinding] = field(default_factory=list)


@dataclass
class ProgramFacts:
    """Cross-function propagated facts keyed by function node id."""

    instances: dict[str, dict[str, set[str]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(set))
    )
    strings: dict[str, dict[str, str]] = field(default_factory=lambda: defaultdict(dict))

    def add_instance(self, func_id: str, var: str, class_name: str) -> bool:
        bucket = self.instances[func_id][var]
        if class_name in bucket:
            return False
        bucket.add(class_name)
        return True

    def add_string(self, func_id: str, var: str, value: str) -> bool:
        if self.strings[func_id].get(var) == value:
            return False
        self.strings[func_id][var] = value
        return True

    def merge_into_state(self, func_id: str, state: FunctionSemanticState) -> None:
        for var, classes in self.instances.get(func_id, {}).items():
            state.instance_classes.setdefault(var, set()).update(classes)
        for var, value in self.strings.get(func_id, {}).items():
            state.string_consts.setdefault(var, value)

    def absorb_summary(self, summary: FunctionSummary) -> bool:
        changed = False
        for var, classes in summary.instance_classes.items():
            for cls in classes:
                if self.add_instance(summary.node_id, var, cls):
                    changed = True
        for var, value in summary.string_consts.items():
            if self.add_string(summary.node_id, var, value):
                changed = True
        return changed

    def propagate_from_summaries(
        self,
        summaries: dict[str, FunctionSummary],
        graph: Any,
    ) -> bool:
        from .models import Relation

        changed = False
        for summary in summaries.values():
            if self.absorb_summary(summary):
                changed = True

        for edge in graph.edges:
            if edge.relation != Relation.CALLS:
                continue
            callee_summary = summaries.get(edge.target)
            caller_summary = summaries.get(edge.source)
            if not callee_summary or not caller_summary:
                continue
            callee_short = edge.target.split("::", 1)[-1].split(".")[-1]
            for binding in caller_summary.call_bindings:
                if not callee_name_matches(binding.callee_name, callee_short, edge.target):
                    continue
                for cls in callee_summary.return_classes:
                    if self.add_instance(edge.source, binding.target_var, cls):
                        changed = True
                for value in callee_summary.return_strings:
                    if self.add_string(edge.source, binding.target_var, value):
                        changed = True
        return changed


def callee_name_matches(binding_name: str, callee_short: str, callee_node_id: str) -> bool:
    label = callee_node_id.split("::", 1)[-1]
    return (
        binding_name == callee_short
        or label == binding_name
        or label.endswith(f".{binding_name}")
        or label.endswith(f"::{binding_name}")
    )


def build_function_summaries(
    graph: Any,
    *,
    language: str,
    source_registry: dict[str, str],
) -> dict[str, FunctionSummary]:
    summaries: dict[str, FunctionSummary] = {}
    for node_id, node in graph.nodes.items():
        if node.kind != "function" or "::" not in node_id:
            continue
        file_path, label = node_id.split("::", 1)
        source = source_registry.get(file_path)
        if not source:
            continue
        summary = _extract_function_summary(
            node_id,
            label=label,
            language=language,
            source=source,
        )
        if summary:
            summaries[node_id] = summary
    return summaries


def _extract_function_summary(
    node_id: str,
    *,
    label: str,
    language: str,
    source: str,
) -> FunctionSummary | None:
    summary = FunctionSummary(node_id=node_id)
    if language == "python":
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
        func = _find_python_function(tree, label)
        if func is None:
            return None
        state = _python_function_state(func, seed_instances={})
        summary.instance_classes = {k: set(v) for k, v in state.instance_classes.items()}
        summary.string_consts = dict(state.string_consts)
        summary.return_classes = _python_return_classes(func)
        summary.return_strings = _python_return_strings(func)
        summary.call_bindings = _python_call_bindings(func)
        return summary

    lang = _get_language(language)
    if lang is None:
        return None
    source_bytes = source.encode("utf-8")
    root = Parser(lang).parse(source_bytes).root_node
    func = _find_treesitter_function(root, label, source_bytes)
    if func is None:
        return None
    state = _treesitter_function_state(func, source_bytes, seed_instances={})
    summary.instance_classes = {k: set(v) for k, v in state.instance_classes.items()}
    summary.string_consts = dict(state.string_consts)
    summary.return_classes = _treesitter_return_classes(func, source_bytes)
    summary.return_strings = _treesitter_return_strings(func, source_bytes)
    summary.call_bindings = _treesitter_call_bindings(func, source_bytes)
    return summary


def _python_call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _python_call_bindings(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[CallSiteBinding]:
    bindings: list[CallSiteBinding] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                callee = _python_call_name(node.value)
                if callee:
                    bindings.append(CallSiteBinding(target_var=target.id, callee_name=callee))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value and isinstance(node.value, ast.Call):
                callee = _python_call_name(node.value)
                if callee:
                    bindings.append(CallSiteBinding(target_var=node.target.id, callee_name=callee))
    return bindings


def _python_return_classes(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    classes: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            classes.add(node.value.func.id)
    return classes


def _python_return_strings(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    strings: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                strings.add(node.value.value)
    return strings


def _treesitter_call_name(node: Node, source_bytes: bytes) -> str | None:
    method = node.child_by_field_name("method")
    if method is not None:
        return source_bytes[method.start_byte : method.end_byte].decode("utf-8")
    func = node.child_by_field_name("function") or node.child_by_field_name("name")
    if func is None:
        return None
    callee = source_bytes[func.start_byte : func.end_byte].decode("utf-8")
    return callee.split(".")[-1]


def _treesitter_call_bindings(func: Node, source_bytes: bytes) -> list[CallSiteBinding]:
    bindings: list[CallSiteBinding] = []

    def text(node: Node) -> str:
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")

    def walk(node: Node) -> None:
        if node.type in (
            "lexical_declaration",
            "variable_declaration",
            "short_var_declaration",
            "var_declaration",
            "assignment_statement",
            "local_variable_declaration",
            "assignment",
            "assignment_expression",
            "expression_statement",
        ):
            if node.type == "assignment_statement":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right and right.type in _TS_CALL_TYPES:
                    left_name = _treesitter_var_name(left, source_bytes)
                    callee = _treesitter_call_name(right, source_bytes)
                    if left_name and callee:
                        bindings.append(
                            CallSiteBinding(target_var=left_name, callee_name=callee)
                        )
            elif node.type in ("assignment", "assignment_expression"):
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right and right.type in _TS_CALL_TYPES:
                    left_name = _treesitter_var_name(left, source_bytes)
                    callee = _treesitter_call_name(right, source_bytes)
                    if left_name and callee:
                        bindings.append(
                            CallSiteBinding(target_var=left_name, callee_name=callee)
                        )
            elif node.type == "expression_statement" and node.children:
                child = node.children[0]
                if child.type == "assignment_expression":
                    left = child.child_by_field_name("left")
                    right = child.child_by_field_name("right")
                    if left and right and right.type in _TS_CALL_TYPES:
                        left_name = _treesitter_var_name(left, source_bytes)
                        callee = _treesitter_call_name(right, source_bytes)
                        if left_name and callee:
                            bindings.append(
                                CallSiteBinding(target_var=left_name, callee_name=callee)
                            )
            else:
                for child in node.children:
                    if child.type != "variable_declarator":
                        continue
                    name_node = child.child_by_field_name("name")
                    value = child.child_by_field_name("value")
                    if name_node is None or value is None:
                        continue
                    if value.type in _TS_CALL_TYPES:
                        callee = _treesitter_call_name(value, source_bytes)
                        if callee:
                            bindings.append(
                                CallSiteBinding(
                                    target_var=text(name_node), callee_name=callee
                                )
                            )
        for child in node.children:
            walk(child)

    body = _function_body_node(func)
    if body:
        walk(body)
    seen: set[tuple[str, str]] = set()
    deduped: list[CallSiteBinding] = []
    for binding in bindings:
        key = (binding.target_var, binding.callee_name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(binding)
    return deduped


_TS_CALL_TYPES = frozenset(
    {
        "call_expression",
        "method_invocation",
        "invocation_expression",
        "function_call_expression",
        "scoped_call_expression",
        "call",
    }
)


def _treesitter_return_classes(func: Node, source_bytes: bytes) -> set[str]:
    classes: set[str] = set()

    def text(node: Node) -> str:
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")

    def walk(node: Node) -> None:
        if node.type in ("return_statement", "return"):
            for child in node.children:
                cls = _class_from_new_node(child, source_bytes)
                if cls:
                    classes.add(cls)
                cls = _class_from_ruby_new_call(child, source_bytes)
                if cls:
                    classes.add(cls)
                if child.type in _TS_CALL_TYPES:
                    callee = _treesitter_call_name(child, source_bytes)
                    if callee and callee[0].isupper():
                        classes.add(callee)
        for child in node.children:
            walk(child)

    body = _function_body_node(func)
    if body:
        walk(body)
        for child in body.children:
            cls = _class_from_ruby_new_call(child, source_bytes)
            if cls:
                classes.add(cls)
            cls = _class_from_new_node(child, source_bytes)
            if cls:
                classes.add(cls)
    return classes


def _treesitter_return_strings(func: Node, source_bytes: bytes) -> set[str]:
    strings: set[str] = set()

    def text(node: Node) -> str:
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")

    def walk(node: Node) -> None:
        if node.type in ("return_statement", "return"):
            for child in node.children:
                if child.type in ("string", "encapsed_string"):
                    strings.add(text(child).strip("'\""))
        for child in node.children:
            walk(child)

    body = _function_body_node(func)
    if body:
        walk(body)
        for child in body.children:
            if child.type in ("string", "encapsed_string"):
                strings.add(text(child).strip("'\""))
    return strings

