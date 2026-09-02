# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Cross-file symbol resolution for the deterministic code graph."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import Any

from tree_sitter import Node, Parser

from ..parser.python_parser import PythonParser
from ..parser.treesitter_parser import _get_language
from ..semantic.treesitter_analyzer import TreeSitterSemanticAnalyzer
from ..semantic.type_analyzer import TypeAnalyzer
from .dynamic_dispatch import (
    is_dynamic_call_label,
    resolve_dynamic_dispatch,
    resolve_python_dynamic_call,
    resolve_virtual_dispatch,
)
from .models import CodeEdge, Provenance, Relation
from .semantic_dispatch import DispatchResult, DispatchTarget, ProgramFacts
_TS_LANGS = frozenset(
    {"javascript", "typescript", "tsx", "go", "rust", "java", "kotlin", "c_sharp", "ruby", "php"}
)


def module_id_for(path: str) -> str:
    return str(Path(path).resolve())


class CrossFileSymbolResolver:
    """Resolve import paths and callee symbols across compilation units."""

    def __init__(
        self,
        files: dict[Path, str],
        *,
        language: str,
        function_nodes: dict[str, Any] | None = None,
    ) -> None:
        self._files = {p.resolve(): src for p, src in files.items()}
        self._language = language
        self._function_nodes = function_nodes or {}
        self._import_map = self._build_import_map()
        self._import_bindings: dict[str, dict[str, str]] = {}
        self._export_bindings: dict[str, dict[str, str]] = {}
        self._wildcard_export_targets: dict[str, list[str]] = defaultdict(list)
        self._import_star_targets: dict[str, list[str]] = defaultdict(list)
        self._py_types: dict[str, TypeAnalyzer] = {}
        self._ts_semantic: dict[str, TreeSitterSemanticAnalyzer] = {}
        self._program_facts: ProgramFacts | None = None
        self._build_semantic_index()

    def set_program_facts(self, facts: ProgramFacts | None) -> None:
        self._program_facts = facts

    @property
    def files(self) -> dict[Path, str]:
        return self._files

    @property
    def import_map(self) -> dict[str, str]:
        return self._import_map

    def _build_import_map(self) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for path in self._files:
            rel = path.name
            mapping[rel] = str(path)
            stem = path.stem
            mapping[stem] = str(path)
            if self._language in ("javascript", "typescript", "tsx"):
                mapping.setdefault(f"./{stem}", str(path))
                mapping.setdefault(f"./{rel}", str(path))
                mapping.setdefault(f"../{stem}", str(path))
            init_path = (path.parent / "__init__.py").resolve()
            if init_path in self._files:
                mapping.setdefault(str(path.parent.name), str(init_path))
        return mapping

    def _build_semantic_index(self) -> None:
        for path, source in self._files.items():
            file_key = str(path)
            if self._language == "python":
                self._index_python_file(path, source, file_key)
            elif self._language in _TS_LANGS:
                self._index_treesitter_file(path, source, file_key)
        self._finalize_wildcard_exports()

    def _index_python_file(self, path: Path, source: str, file_key: str) -> None:
        try:
            parser = PythonParser(path, source)
            parser.parse()
            type_analyzer = TypeAnalyzer(parser)
            type_analyzer.analyze()
            self._py_types[file_key] = type_analyzer
            self._import_bindings[file_key] = self._parse_python_import_bindings(source, file_key)
            self._export_bindings[file_key] = self._parse_python_export_bindings(
                source, file_key
            )
        except Exception:
            return

    def _index_treesitter_file(self, path: Path, source: str, file_key: str) -> None:
        lang = self._language
        if lang == "tsx":
            lang = "tsx"
        language = _get_language(lang)
        if language is None:
            return
        try:
            source_bytes = source.encode("utf-8")
            parser = Parser(language)
            tree = parser.parse(source_bytes)
            semantic = TreeSitterSemanticAnalyzer(lang, tree.root_node, source_bytes)
            semantic.analyze()
            self._ts_semantic[file_key] = semantic
            self._import_bindings[file_key] = self._parse_ts_import_bindings(
                tree.root_node, source_bytes, file_key
            )
            self._export_bindings[file_key] = self._parse_ts_export_bindings(
                tree.root_node, source_bytes, file_key
            )
        except Exception:
            return

    def _parse_python_import_bindings(self, source: str, file_key: str) -> dict[str, str]:
        bindings: dict[str, str] = {}
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return bindings

        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    target = self.resolve_import_target(alias.name, importer=file_key)
                    if target:
                        bindings[local] = target
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                base = self.resolve_import_target(module, importer=file_key) if module else None
                for alias in node.names:
                    if alias.name == "*":
                        if base:
                            self._import_star_targets[file_key].append(base)
                        continue
                    local = alias.asname or alias.name
                    if base:
                        bindings[local] = f"{base}::{alias.name}"
                    elif module:
                        bindings[local] = module
        return bindings

    def _parse_python_export_bindings(self, source: str, file_key: str) -> dict[str, str]:
        exports: dict[str, str] = {}
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return exports

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith("_"):
                    exports[node.name] = f"{file_key}::{node.name}"
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                base = self.resolve_import_target(module, importer=file_key) if module else None
                for alias in node.names:
                    if alias.name == "*":
                        if base:
                            self._wildcard_export_targets[file_key].append(base)
                        continue
                    exported = alias.name
                    local = alias.asname or exported
                    if base:
                        exports[local] = f"{base}::{exported}"
        return exports

    def _parse_ts_import_bindings(
        self, root: Node, source_bytes: bytes, file_key: str
    ) -> dict[str, str]:
        bindings: dict[str, str] = {}

        def visit(node: Node) -> None:
            if node.type == "import_statement":
                source_node = node.child_by_field_name("source")
                if source_node is None:
                    return
                import_path = source_bytes[
                    source_node.start_byte : source_node.end_byte
                ].decode("utf-8").strip("'\"")
                target_file = self.resolve_import_target(import_path, importer=file_key)
                if not target_file:
                    return

                for child in node.children:
                    if child.type == "import_clause":
                        for clause_child in child.children:
                            if clause_child.type == "identifier":
                                local = clause_child.text.decode("utf-8")
                                bindings[local] = target_file
                            elif clause_child.type == "named_imports":
                                for spec in clause_child.children:
                                    if spec.type == "import_specifier":
                                        name_node = spec.child_by_field_name("name")
                                        alias_node = spec.child_by_field_name("alias")
                                        if name_node is None:
                                            continue
                                        exported = name_node.text.decode("utf-8")
                                        local = (
                                            alias_node.text.decode("utf-8")
                                            if alias_node
                                            else exported
                                        )
                                        bindings[local] = f"{target_file}::{exported}"
                            elif clause_child.type == "namespace_import":
                                alias = clause_child.child_by_field_name("name")
                                if alias:
                                    bindings[alias.text.decode("utf-8")] = target_file
            for child in node.children:
                visit(child)

        visit(root)
        return bindings

    def _parse_ts_export_bindings(
        self, root: Node, source_bytes: bytes, file_key: str
    ) -> dict[str, str]:
        exports: dict[str, str] = {}

        def visit(node: Node) -> None:
            if node.type == "export_statement":
                source_node = next(
                    (child for child in node.children if child.type == "string"),
                    None,
                )
                export_clause = next(
                    (child for child in node.children if child.type == "export_clause"),
                    None,
                )
                if source_node is not None and export_clause is not None:
                    import_path = source_bytes[
                        source_node.start_byte : source_node.end_byte
                    ].decode("utf-8").strip("'\"")
                    target_file = self.resolve_import_target(import_path, importer=file_key)
                    if target_file:
                        for spec in export_clause.children:
                            if spec.type != "export_specifier":
                                continue
                            name_node = spec.child_by_field_name("name")
                            alias_node = spec.child_by_field_name("alias")
                            if name_node is None:
                                continue
                            exported = name_node.text.decode("utf-8")
                            local = (
                                alias_node.text.decode("utf-8") if alias_node else exported
                            )
                            exports[local] = f"{target_file}::{exported}"
                elif source_node is not None and any(
                    child.type == "*" for child in node.children
                ):
                    import_path = source_bytes[
                        source_node.start_byte : source_node.end_byte
                    ].decode("utf-8").strip("'\"")
                    target_file = self.resolve_import_target(import_path, importer=file_key)
                    if target_file:
                        self._wildcard_export_targets[file_key].append(target_file)
                else:
                    for child in node.children:
                        if child.type in (
                            "function_declaration",
                            "class_declaration",
                            "lexical_declaration",
                        ):
                            name_node = child.child_by_field_name("name")
                            if name_node is not None:
                                exports[name_node.text.decode("utf-8")] = (
                                    f"{file_key}::{name_node.text.decode('utf-8')}"
                                )
            for child in node.children:
                visit(child)

        visit(root)
        return exports

    def _exports_for_file(self, file_key: str, *, _visited: set[str] | None = None) -> dict[str, str]:
        visited = _visited or set()
        if file_key in visited:
            return {}
        visited.add(file_key)
        merged = dict(self._export_bindings.get(file_key, {}))
        for target in self._wildcard_export_targets.get(file_key, []):
            for name, binding in self._exports_for_file(target, _visited=visited).items():
                merged.setdefault(name, binding)
        return merged

    def _finalize_wildcard_exports(self) -> None:
        for file_key, targets in self._import_star_targets.items():
            bindings = self._import_bindings.setdefault(file_key, {})
            for target in targets:
                for name, binding in self._exports_for_file(target).items():
                    bindings.setdefault(name, binding)
        for file_key in list(self._export_bindings.keys()):
            self._export_bindings[file_key] = self._exports_for_file(file_key)
        for file_key, targets in self._wildcard_export_targets.items():
            if file_key not in self._export_bindings:
                self._export_bindings[file_key] = self._exports_for_file(file_key)

    def resolve_import_target(self, import_path: str, *, importer: str = "") -> str | None:
        cleaned = import_path.strip().strip("'\"")
        if cleaned in self._import_map:
            return self._import_map[cleaned]
        if cleaned.startswith(".") and importer:
            resolved = self._resolve_relative_import(cleaned, importer)
            if resolved:
                return resolved
        if cleaned.startswith("."):
            for key, target in self._import_map.items():
                if cleaned.endswith(Path(key).stem) or key.endswith(cleaned.lstrip("./")):
                    return target
        candidate = cleaned.replace("/", ".").split(".")[-1]
        for key, target in self._import_map.items():
            if key.endswith(candidate) or Path(target).stem == candidate:
                return target
        return None

    def _resolve_relative_import(self, import_path: str, importer: str) -> str | None:
        importer_path = Path(importer)
        if importer_path.is_file():
            base_dir = importer_path.parent
        else:
            base_dir = importer_path
        candidate = (base_dir / import_path).resolve()
        if candidate.suffix:
            if candidate in self._files:
                return str(candidate)
            return str(candidate) if candidate.exists() else None
        for suffix in (
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".mjs",
            ".py",
            ".java",
            ".kt",
            ".kts",
            ".cs",
            ".rb",
            ".php",
            ".go",
            ".rs",
        ):
            probe = candidate.with_suffix(suffix)
            if probe in self._files:
                return str(probe)
        init_probe = candidate / "__init__.py"
        if init_probe in self._files:
            return str(init_probe)
        index_probe = candidate / "index.ts"
        if index_probe in self._files:
            return str(index_probe)
        for index_name in ("index.js", "index.tsx", "index.mjs"):
            probe = candidate / index_name
            if probe in self._files:
                return str(probe)
        return None

    def _resolve_binding_chain(self, binding: str, *, depth: int = 0) -> str:
        if depth > 6 or "::" not in binding:
            return binding
        target_file, symbol = binding.split("::", 1)
        if "." in symbol:
            return binding
        exports = self._export_bindings.get(target_file, {})
        next_binding = exports.get(symbol)
        if not next_binding or next_binding == binding:
            for wildcard_target in self._wildcard_export_targets.get(target_file, []):
                wildcard_exports = self._export_bindings.get(wildcard_target, {})
                next_binding = wildcard_exports.get(symbol)
                if next_binding:
                    break
        if not next_binding or next_binding == binding:
            return binding
        return self._resolve_binding_chain(next_binding, depth=depth + 1)

    def _resolve_imported_symbol(self, caller_file: str, local_name: str) -> str | None:
        binding = self._import_bindings.get(caller_file, {}).get(local_name)
        if not binding:
            return None
        if "::" not in binding:
            return binding
        return self._resolve_binding_chain(binding)

    def _match_known_function(
        self,
        binding: str,
        known_functions: set[str],
    ) -> str | None:
        if "::" not in binding:
            return None
        target_file, symbol = binding.split("::", 1)
        candidate = f"{target_file}::{symbol}"
        if candidate in known_functions:
            return candidate
        short = symbol.split(".")[-1]
        matches = [
            fn
            for fn in known_functions
            if fn.startswith(f"{target_file}::") and fn.endswith(f"::{short}")
        ]
        if len(matches) == 1:
            return matches[0]
        suffix = f"::{short}"
        exact = [fn for fn in known_functions if fn.endswith(suffix)]
        if len(exact) == 1:
            return exact[0]
        return None

    def _semantic_for_file(self, file_key: str) -> TypeAnalyzer | TreeSitterSemanticAnalyzer | None:
        return self._py_types.get(file_key) or self._ts_semantic.get(file_key)

    def _source_for_file(self, caller_file: str) -> str | None:
        return self._files.get(Path(caller_file).resolve())

    def resolve_callee_targets(
        self,
        caller_id: str,
        callee_label: str,
        known_functions: set[str],
    ) -> DispatchResult:
        """Resolve one or more callee targets for a call site."""
        caller_file = caller_id.split("::", 1)[0] if "::" in caller_id else ""
        caller_label = caller_id.split("::", 1)[-1] if "::" in caller_id else caller_id
        source = self._source_for_file(caller_file)
        semantic = self._semantic_for_file(caller_file)

        if is_dynamic_call_label(callee_label):
            if self._language == "python" and source:
                return resolve_python_dynamic_call(
                    callee_label,
                    source=source,
                    caller_label=caller_label,
                    semantic=semantic if isinstance(semantic, TypeAnalyzer) else None,
                    known_functions=known_functions,
                    caller_file=caller_file,
                    program_facts=self._program_facts,
                    caller_node_id=caller_id,
                )
            if source:
                return resolve_dynamic_dispatch(
                    callee_label,
                    language=self._language,
                    source=source,
                    caller_label=caller_label,
                    caller_file=caller_file,
                    semantic=semantic,
                    known_functions=known_functions,
                    program_facts=self._program_facts,
                    caller_node_id=caller_id,
                )
            return DispatchResult()

        single = self._resolve_static_callee(
            caller_id,
            callee_label,
            known_functions,
            caller_file=caller_file,
            caller_label=caller_label,
            source=source,
            semantic=semantic,
        )
        if single.targets:
            return single
        return DispatchResult()

    def _resolve_static_callee(
        self,
        caller_id: str,
        callee_label: str,
        known_functions: set[str],
        *,
        caller_file: str,
        caller_label: str,
        source: str | None,
        semantic: TypeAnalyzer | TreeSitterSemanticAnalyzer | None,
    ) -> DispatchResult:
        resolved, provenance, confidence, context = self.resolve_callee(
            caller_id,
            callee_label,
            known_functions,
            _skip_dynamic=True,
        )
        if not resolved.startswith("external::"):
            return DispatchResult(
                targets=[
                    DispatchTarget(
                        node_id=resolved,
                        confidence=confidence,
                        context=context or "static",
                    )
                ]
            )

        if source and "." in callee_label and semantic:
            virtual = resolve_virtual_dispatch(
                callee_label,
                language=self._language,
                source=source,
                caller_label=caller_label,
                caller_file=caller_file,
                semantic=semantic,
                known_functions=known_functions,
                program_facts=self._program_facts,
                caller_node_id=caller_id,
            )
            if virtual.targets:
                return virtual
        return DispatchResult()

    def resolve_callee(
        self,
        caller_id: str,
        callee_label: str,
        known_functions: set[str],
        *,
        _skip_dynamic: bool = False,
    ) -> tuple[str, Provenance, float, str | None]:
        """Return (resolved_id, provenance, confidence, call_context)."""
        context: str | None = None
        caller_file = caller_id.split("::", 1)[0] if "::" in caller_id else ""
        caller_label = caller_id.split("::", 1)[-1] if "::" in caller_id else caller_id

        if not _skip_dynamic and is_dynamic_call_label(callee_label):
            dispatch = self.resolve_callee_targets(caller_id, callee_label, known_functions)
            primary = dispatch.primary()
            if primary:
                return (
                    primary.node_id,
                    dispatch.provenance,
                    primary.confidence,
                    primary.context,
                )
            context = "dynamic_dispatch"
            sink_id = f"external::{callee_label}"
            return sink_id, Provenance.AMBIGUOUS, 0.5, context

        if "::" in callee_label and callee_label in known_functions:
            return callee_label, Provenance.EXTRACTED, 1.0, None

        if "." not in callee_label:
            imported = self._resolve_imported_symbol(caller_file, callee_label)
            if imported:
                matched = self._match_known_function(imported, known_functions)
                if matched:
                    return matched, Provenance.EXTRACTED, 0.95, "barrel_reexport"

        semantic = self._semantic_for_file(caller_file)
        if semantic and "." in callee_label:
            resolved_method = semantic.resolve_method_call(callee_label)
            if resolved_method:
                for fn in known_functions:
                    if fn.endswith(f"::{resolved_method}"):
                        return fn, Provenance.EXTRACTED, 1.0, "semantic_method"

            prefix, _, member = callee_label.partition(".")
            binding = self._import_bindings.get(caller_file, {}).get(prefix)
            if binding:
                if "::" in binding:
                    target_file, symbol = binding.split("::", 1)
                    candidate = f"{target_file}::{symbol}.{member}" if member else f"{target_file}::{symbol}"
                else:
                    candidate = f"{binding}::{member}" if member else binding
                if candidate in known_functions:
                    return candidate, Provenance.EXTRACTED, 0.95, "import_binding"
                for fn in known_functions:
                    if fn.startswith(f"{binding}::") and fn.endswith(f".{member}"):
                        return fn, Provenance.INFERRED, 0.9, "import_binding"

        short = callee_label.split(".")[-1]
        same_file = sorted(
            fn
            for fn in known_functions
            if fn.startswith(f"{caller_file}::")
            and (
                fn.endswith(f"::{callee_label}")
                or fn.endswith(f".{short}")
                or fn.endswith(f"::{short}")
            )
        )
        if len(same_file) == 1:
            return same_file[0], Provenance.EXTRACTED, 1.0, None

        cross_file = sorted(
            fn
            for fn in known_functions
            if fn.endswith(f".{short}") or fn.endswith(f"::{short}")
        )
        if len(cross_file) == 1:
            return cross_file[0], Provenance.INFERRED, 0.8, "cross_file_suffix"
        if len(cross_file) > 1:
            return cross_file[0], Provenance.AMBIGUOUS, 0.5, "ambiguous_suffix"

        if callee_label in known_functions:
            return callee_label, Provenance.INFERRED, 0.75, None

        imported = self._resolve_imported_symbol(caller_file, callee_label.split(".")[0])
        if imported and not callee_label.startswith("external::"):
            short = callee_label.split(".")[-1]
            matched = self._match_known_function(
                imported if "." not in callee_label else f"{imported.rsplit('::',1)[0]}::{short}",
                known_functions,
            )
            if matched:
                return matched, Provenance.INFERRED, 0.9, "import_symbol"
            for fn in known_functions:
                target_file = imported.split("::", 1)[0] if "::" in imported else imported
                if fn.startswith(f"{target_file}::") and fn.endswith(f"::{short}"):
                    return fn, Provenance.INFERRED, 0.85, "import_symbol"

        return f"external::{callee_label}", Provenance.INFERRED, 0.75, None

    def import_edges(self) -> list[CodeEdge]:
        edges: list[CodeEdge] = []
        for path, source in self._files.items():
            module = str(path)
            for line in source.splitlines():
                stripped = line.strip()
                if self._language == "python" and stripped.startswith(("import ", "from ")):
                    target = self.resolve_import_target(stripped.split()[-1])
                    if target:
                        edges.append(
                            CodeEdge(
                                source=f"{module}::__module__",
                                target=target,
                                relation=Relation.IMPORTS,
                                provenance=Provenance.EXTRACTED,
                                confidence_score=1.0,
                                context=stripped[:120],
                            )
                        )
                elif self._language in ("javascript", "typescript", "tsx") and "from " in stripped:
                    parts = stripped.replace("from", " ").replace("import", " ").split()
                    if parts:
                        target = self.resolve_import_target(parts[0])
                        if target:
                            edges.append(
                                CodeEdge(
                                    source=f"{module}::__module__",
                                    target=target,
                                    relation=Relation.IMPORTS,
                                    provenance=Provenance.EXTRACTED,
                                    confidence_score=1.0,
                                    context=stripped[:120],
                                )
                            )
        return edges
