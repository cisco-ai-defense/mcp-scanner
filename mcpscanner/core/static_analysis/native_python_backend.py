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

"""The ``ast``-based backend of :class:`~.native_analyzer.NativeAnalyzer`.

Everything here reads a Python AST. It is mixed into ``NativeAnalyzer``
rather than held as a collaborator because both backends work directly on
the analyzer's per-file state -- source bytes, line index, taint
environment, caches -- and handing that across an object boundary would be
a rewrite rather than a move.
"""

import ast
import re as _re

from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

from .context_extractor import FunctionContext
from .dataflow.forward_analysis import ForwardDataflowAnalysis
from .parser.python_parser import PythonParser
from .taint.tracker import TaintStatus

from .native_common import (
    TaintInfo,
    _MCP_KNOWN_SERVER_CLASSES,
    _MCP_SDK_MODULE_PREFIXES,
    _normalize_module_specifier,
    _python_decorator_capability,
)


class PythonBackendMixin:
    """Python capability extraction, mixed into ``NativeAnalyzer``."""

    def _py_collect_import_targets(
        self, stmt: str, out: Dict[str, List[str]]
    ) -> None:
        """Populate ``out`` from one Python import statement."""
        # ``from <module> import X [as Y], ...``
        m = _re.match(r"^from\s+(\S+)\s+import\s+(.+?)\s*$", stmt)
        if m:
            module = _normalize_module_specifier(m.group(1))
            for piece in m.group(2).split(","):
                piece = piece.strip().rstrip(")").lstrip("(")
                if not piece or piece == "*":
                    continue
                parts = _re.split(r"\s+as\s+", piece, maxsplit=1)
                orig = parts[0].strip()
                bound = parts[1].strip() if len(parts) > 1 else orig
                if not bound:
                    continue
                # ``orig`` could either be a function within ``module``
                # or a submodule of ``module`` (when used like
                # ``from .tools import docs`` to bind a module). Record
                # both candidates so the resolver can pick whichever
                # actually exists in the call graph.
                if module:
                    out.setdefault(bound, []).append(module)
                    out[bound].append(f"{module}/{orig}")
                else:
                    out.setdefault(bound, []).append(orig)
            return
        # ``import M [as N]`` or ``import M.sub``
        m = _re.match(r"^import\s+([\w\.]+)(?:\s+as\s+(\w+))?\s*$", stmt)
        if m:
            full = m.group(1)
            alias = m.group(2)
            bound = alias or full.split(".", 1)[0]
            out.setdefault(bound, []).append(_normalize_module_specifier(full))
    def _py_extract_capability_contexts(
        self,
        *,
        cross_file_analyzer: Any = None,
    ) -> List[FunctionContext]:
        """Lazy Python capability extraction (Gap 5 + Gap 8).

        The previous implementation called ``extract_all_function_contexts``
        which forced a full ForwardDataflowAnalysis pass on every helper
        function in the file *before* filtering them out — defeating the
        purpose of the capability extractor on helper-heavy modules.

        The new path:

          1. Run the byte-level prefilter once. If the file has no MCP
             markers, return ``[]`` without parsing.
          2. ``ast.parse`` once.
          3. Walk the AST and collect:
             a. ``FunctionDef`` / ``AsyncFunctionDef`` nodes whose
                decorator list names an MCP capability (FastMCP
                shorthand or low-level Server).
             b. Wrapper-decorator targets (Gap 8): functions decorated
                with custom wrappers that internally call
                ``mcp.tool(...)``. Detected via a per-file scan that
                identifies wrapper definitions like
                ``def safe_tool(fn): return mcp.tool()(fn)``.
             c. Programmatic ``mcp.add_tool(handler)`` /
                ``server.add_tool(handler)`` calls (Gap 8): emit the
                handler if it's a known function, an unresolved stub
                otherwise.
          4. Run the expensive ``_py_extract_function`` (which triggers
             dataflow analysis) ONLY on the filtered candidates.

        Failure modes:

        - The byte-level prefilter rejects files with no MCP markers
          (returns ``[]`` immediately).
        - ``ast.parse`` failures on unparseable Python return ``[]``.
        - Per-function extraction failures (in
          ``_py_extract_function`` or the programmatic-registration
          handler resolver) are logged at ``DEBUG`` and skipped
          individually; one bad function does not abort the whole pass.

        There is intentionally no outer try/except that re-runs the
        legacy ``extract_all_function_contexts`` path. An earlier draft
        of this docstring claimed otherwise — that promise was removed
        because falling back to the legacy walker would re-introduce
        the helper-bloat regression this method was written to fix
        (every plain helper would be sent to dataflow analysis).
        """
        if not self._has_mcp_markers():
            return []
        try:
            tree = ast.parse(self.source_code, filename=str(self.file_path))
        except SyntaxError:
            return []

        module_imports = self._py_extract_imports(tree)
        wrapper_decorators = self._py_collect_wrapper_decorators(tree)
        # Identify trusted MCP server-instance names so
        # ``@<receiver>.tool`` only classifies when ``<receiver>``
        # actually binds to an MCP SDK instance.
        mcp_instances = self._py_collect_mcp_instances(tree, module_imports)

        # Build the import-target map once per call so the cross-file
        # resolver can disambiguate same-named functions via the
        # calling file's own import paths.
        import_target_map = self._build_import_target_map(
            module_imports,
            current_file=str(self.file_path) if self.file_path else None,
        )

        functions_by_name: Dict[
            str, Union[ast.FunctionDef, ast.AsyncFunctionDef]
        ] = {}
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions_by_name.setdefault(n.name, n)

        # Class-method index for ``self.<method>`` resolution at
        # registration call sites (Gap 8 extension).
        class_methods = self._py_build_class_method_index(tree)

        contexts: List[FunctionContext] = []
        seen: Set["tuple[Any, str]"] = set()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorator_names = [
                self._py_get_node_name(dec) for dec in (node.decorator_list or [])
            ]
            cap_kind = self._py_classify_decorators(
                decorator_names,
                wrapper_decorators,
                trusted_receivers=mcp_instances,
            )
            if cap_kind is None:
                continue
            cap_key = (node.lineno, cap_kind)
            if cap_key in seen:
                continue
            seen.add(cap_key)
            try:
                ctx = self._py_extract_function(node, module_imports)
            except Exception as e:
                self.logger.debug(
                    f"Failed to extract MCP capability {node.name!r} from "
                    f"{self.file_path}: {e}"
                )
                continue
            contexts.append(ctx)

        # Gap 8: programmatic registrations.
        # Covers both ``mcp.add_tool(fn)`` and the
        # ``mcp.tool(...)(self.method)`` decorator-factory-on-bound-method
        # pattern (used by AWS-Labs-style tool-group classes). Handlers
        # we cannot resolve in-file (cross-file references, factory
        # calls, etc.) become cross-file or unresolved-handler stubs so
        # the LLM / report layer still sees a capability was
        # registered.
        for (
            handler_node,
            label,
            cap_kind,
            cross_file_path,
        ) in self._py_iter_programmatic_registrations(
            tree,
            functions_by_name=functions_by_name,
            class_methods=class_methods,
            cross_file_analyzer=cross_file_analyzer,
            import_target_map=import_target_map,
        ):
            if handler_node is None and cross_file_path is not None:
                # Cross-file resolution succeeded — emit a
                # ``registration.cross_file`` stub like the TS path so
                # consumers can show the user where the handler lives.
                stub_key = (("crossfile", cross_file_path, label), cap_kind)
                if stub_key in seen:
                    continue
                seen.add(stub_key)
                self._append_unresolved_capability(
                    contexts,
                    capability=cap_kind,
                    registered_name=label,
                    source_kind="registration.cross_file",
                    handler_name_hint=label,
                    source_file=cross_file_path,
                )
                continue
            if handler_node is None:
                stub_key = (("unresolved", label), cap_kind)
                if stub_key in seen:
                    continue
                seen.add(stub_key)
                self._append_unresolved_capability(
                    contexts,
                    capability=cap_kind,
                    registered_name=label,
                    source_kind="registration.unresolved",
                    handler_name_hint=label,
                )
                continue
            cap_key = (handler_node.lineno, cap_kind)
            if cap_key in seen:
                continue
            seen.add(cap_key)
            try:
                ctx = self._py_extract_function(handler_node, module_imports)
            except Exception as e:
                self.logger.debug(
                    f"Failed to extract programmatic MCP capability "
                    f"{label!r}: {e}"
                )
                continue
            ctx.decorator_types.append(f"<registration>.{cap_kind}")
            contexts.append(ctx)

        return contexts
    def _py_collect_wrapper_decorators(self, tree: ast.AST) -> Dict[str, str]:
        """Identify custom decorator wrappers that delegate to an MCP
        decorator (Gap 8).

        Recognizes the common pattern::

            def safe_tool(fn):
                return mcp.tool()(fn)

        Returns ``{wrapper_name: capability_kind}``. Wrappers found here
        are accepted by ``_py_classify_decorators`` so a function
        decorated with ``@safe_tool`` is classified as a tool even
        though no built-in MCP decorator name appears on it.
        """
        wrappers: Dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Wrappers usually take a single arg (``fn``) and return a
            # call expression that invokes an MCP decorator on it.
            for ret in (
                stmt
                for stmt in ast.walk(node)
                if isinstance(stmt, ast.Return)
            ):
                if ret.value is None:
                    continue
                cap = self._py_call_returns_mcp_decoration(ret.value)
                if cap is not None:
                    wrappers[node.name] = cap
                    break
        return wrappers
    def _py_call_returns_mcp_decoration(
        self, expr: ast.AST
    ) -> Optional[str]:
        """Return the capability kind if ``expr`` is a call expression
        that ultimately invokes ``mcp.tool``/``mcp.prompt``/``mcp.resource``
        (or one of the low-level server decorators) and applies it to a
        function. Used to detect wrapper decorators (Gap 8)."""
        if not isinstance(expr, ast.Call):
            return None
        # ``mcp.tool()(fn)`` parses as Call(Call(...), [fn])
        inner = expr.func
        if isinstance(inner, ast.Call):
            return self._py_call_returns_mcp_decoration(inner)
        # Plain attribute access: ``server.add_tool(fn)`` etc.
        name_text = self._py_get_node_name(inner)
        if not name_text:
            return None
        return _python_decorator_capability(name_text)
    def _py_classify_decorators(
        self,
        decorator_names: List[str],
        wrapper_decorators: Dict[str, str],
        *,
        trusted_receivers: Optional[Set[str]] = None,
    ) -> Optional[str]:
        """Return the canonical capability kind for ``decorator_names``.

        Accepts both built-in MCP decorators (FastMCP / low-level
        Server) and locally-defined wrapper decorators discovered via
        ``_py_collect_wrapper_decorators``.

        Receiver verification (Gap 4 parity):
        when ``trusted_receivers`` is non-empty, decorators of the form
        ``@<receiver>.<method>`` only classify as MCP if ``<receiver>``
        is a known MCP server instance bound in this file. Bare
        decorators (``@tool``, no dot) are always accepted because they
        can only have come from a direct symbol import. When the
        receiver set is empty (provenance pass found nothing) we apply
        the same "loose if empty" tradeoff as TS so unusual import
        patterns still work.
        """
        for name in decorator_names or []:
            kind = _python_decorator_capability(name)
            if kind is not None:
                if trusted_receivers and "." in name:
                    receiver = name.rsplit(".", 1)[0].strip()
                    # Strip any call-args so ``foo(args).tool`` reduces
                    # to ``foo`` for receiver lookup.
                    receiver_root = receiver.split(".", 1)[0].split("(", 1)[0]
                    if receiver_root not in trusted_receivers:
                        # Receiver isn't a known MCP instance; reject
                        # this decorator and keep scanning the list —
                        # another decorator on the same function may
                        # still be a valid MCP capability.
                        continue
                return kind
            bare = name.rsplit(".", 1)[-1].split("(", 1)[0].strip()
            wrapped = wrapper_decorators.get(bare)
            if wrapped:
                return wrapped
        return None
    def _py_collect_mcp_instances(
        self, tree: ast.AST, module_imports: List[str]
    ) -> Set[str]:
        """Identify Python local names bound to an MCP server instance.

        AST-based mirror of :meth:`_collect_mcp_instances` (which runs
        on tree-sitter): the lazy Python path doesn't have a tree-sitter
        tree available, so we walk ``ast`` instead. Recognized
        provenance shapes::

            mcp = FastMCP("demo")                          # Assign
            server = Server()                              # Assign
            mcp = mcp.server.fastmcp.FastMCP(...)          # Assign
            mcp: FastMCP = ...                             # AnnAssign
            def f(server: Server): ...                     # parameter
            class S:
                def m(self, server: FastMCP): ...          # parameter

        SDK class names are sourced from this file's ``from <mcp-sdk>
        import X [as Y]`` statements (so locally-renamed classes still
        match) plus the global ``_MCP_KNOWN_SERVER_CLASSES`` allow-list
        as a backstop for unusual import shapes.

        Returns the union of bound instance names and SDK package
        aliases. Returns an empty set when no SDK import is detected so
        the caller can fall back to loose receiver matching rather than
        silently dropping registrations.
        """
        prefixes = _MCP_SDK_MODULE_PREFIXES.get("python", ())
        if not prefixes:
            return set()

        sdk_classes: Set[str] = set()
        sdk_aliases: Set[str] = set()
        for stmt in module_imports or []:
            stmt_lc = stmt.lower()
            if not any(p in stmt_lc for p in prefixes):
                continue
            # ``from <module> import X [as Y], Z, ...``
            m = _re.match(r"^\s*from\s+([\w\.]+)\s+import\s+(.+)$", stmt)
            if m:
                for sym in m.group(2).split(","):
                    sym = sym.strip()
                    parts = _re.split(r"\s+as\s+", sym, maxsplit=1)
                    bound = (
                        parts[1].strip()
                        if len(parts) > 1
                        else parts[0].strip()
                    )
                    if not bound:
                        continue
                    # Heuristic: PascalCase = class, snake_case / lower
                    # = module alias. Cheap and accurate for SDK code.
                    if bound[:1].isupper():
                        sdk_classes.add(bound)
                    else:
                        sdk_aliases.add(bound)
                continue
            # ``import <module> [as alias]`` — bind the alias.
            m = _re.match(r"^\s*import\s+([\w\.]+)(?:\s+as\s+(\w+))?\s*$", stmt)
            if m:
                full = m.group(1)
                alias = m.group(2)
                bound = alias or full.split(".", 1)[0]
                sdk_aliases.add(bound)

        # Backstop allow-list: even if the import line was unusual, a
        # call to ``FastMCP(...)`` / ``Server(...)`` should bind a
        # trusted receiver. Same names tree-sitter uses.
        sdk_classes.update(_MCP_KNOWN_SERVER_CLASSES)

        trusted: Set[str] = set(sdk_aliases)

        def _matches_sdk_class(call_or_attr: ast.AST) -> bool:
            """Return True if the node names an MCP SDK class."""
            full = ""
            if isinstance(call_or_attr, ast.Call):
                full = self._py_get_node_name(call_or_attr.func)
            elif isinstance(call_or_attr, (ast.Attribute, ast.Name)):
                full = self._py_get_node_name(call_or_attr)
            if not full:
                return False
            leaf = full.rsplit(".", 1)[-1].split("(", 1)[0].strip()
            return leaf in sdk_classes

        for node in ast.walk(tree):
            # ``mcp = FastMCP("demo")``
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _matches_sdk_class(node.value):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            trusted.add(tgt.id)
            # ``mcp: FastMCP = FastMCP(...)`` or just the annotation.
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                ann_text = self._py_unparse_safe(node.annotation)
                leaf = ann_text.rsplit(".", 1)[-1] if ann_text else ""
                if leaf in sdk_classes:
                    trusted.add(node.target.id)
                if isinstance(node.value, ast.Call) and _matches_sdk_class(node.value):
                    trusted.add(node.target.id)
            # Function-parameter type annotations:
            # ``def f(server: FastMCP): ...``
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params: List[ast.arg] = []
                params.extend(node.args.args or [])
                params.extend(node.args.kwonlyargs or [])
                if node.args.vararg is not None:
                    params.append(node.args.vararg)
                if node.args.kwarg is not None:
                    params.append(node.args.kwarg)
                for arg in params:
                    if arg.annotation is None:
                        continue
                    ann_text = self._py_unparse_safe(arg.annotation)
                    leaf = ann_text.rsplit(".", 1)[-1] if ann_text else ""
                    if leaf in sdk_classes:
                        trusted.add(arg.arg)

        return trusted
    # ``<obj>.<method>(handler)`` — direct programmatic registration.
    _PY_PROGRAMMATIC_METHOD_TO_KIND: Dict[str, str] = {
        "add_tool": "tool",
        "register_tool": "tool",
        "add_prompt": "prompt",
        "register_prompt": "prompt",
        "add_resource": "resource",
        "register_resource": "resource",
        "add_resource_template": "resource",
        "add_prompt_template": "prompt",
    }
    # ``<obj>.<method>(...)(handler)`` — decorator factory applied to a
    # bound method or function reference. Includes both the FastMCP
    # high-level shorthand and the low-level ``Server`` decorators that
    # users sometimes invoke programmatically (e.g. tests, dynamic
    # registration).
    _PY_DECORATOR_FACTORY_METHOD_TO_KIND: Dict[str, str] = {
        "tool": "tool",
        "prompt": "prompt",
        "resource": "resource",
        "resource_template": "resource",
        "prompt_template": "prompt",
        "call_tool": "tool",
        "list_tools": "tool",
        "list_prompts": "prompt",
        "get_prompt": "prompt",
        "list_resources": "resource",
        "list_resource_templates": "resource",
        "read_resource": "resource",
    }
    def _py_build_class_method_index(
        self, tree: ast.AST
    ) -> Dict[str, Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]]:
        """Index ``{class_name: {method_name: FunctionDef}}`` for the file.

        Used to resolve ``self.<method>`` references at registration call
        sites such as ``mcp.tool(name='x')(self.do_thing)`` (Gap 8).
        Nested classes shadow earlier definitions of the same name; we
        keep the first occurrence for stability.
        """
        out: Dict[str, Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]] = {}
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            methods: Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]] = {}
            for stmt in cls.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.setdefault(stmt.name, stmt)
            if methods:
                out.setdefault(cls.name, methods)
        return out
    def _py_walk_calls_with_class_context(
        self, node: ast.AST, class_stack: List[str]
    ) -> Iterator["tuple[ast.Call, Optional[str]]"]:
        """Yield ``(Call, enclosing_class_name)`` for every ``ast.Call``.

        Tracks the innermost enclosing ``ClassDef`` so callers can resolve
        ``self.<method>`` handler references against the correct class.
        Nested classes push onto the stack; the current class is the top
        of the stack.
        """
        if isinstance(node, ast.Call):
            yield node, (class_stack[-1] if class_stack else None)
        if isinstance(node, ast.ClassDef):
            new_stack = class_stack + [node.name]
        else:
            new_stack = class_stack
        for child in ast.iter_child_nodes(node):
            yield from self._py_walk_calls_with_class_context(child, new_stack)
    def _py_resolve_handler_expr(
        self,
        handler: ast.expr,
        enclosing_cls: Optional[str],
        class_methods: Dict[
            str, Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]
        ],
        functions_by_name: Dict[
            str, Union[ast.FunctionDef, ast.AsyncFunctionDef]
        ],
        *,
        cross_file_analyzer: Any = None,
        import_target_map: Optional[Dict[str, List[str]]] = None,
    ) -> "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str, Optional[str]]":
        """Resolve a handler expression at a registration call site.

        Returns ``(function_node_or_None, human_label, cross_file_path_or_None)``.

        * ``function_node`` is non-None when the handler resolves to a
          local AST node we can run dataflow on.
        * ``cross_file_path`` is non-None when in-file resolution failed
          but the cross-file call graph located the defining file. The
          caller should emit a ``registration.cross_file`` stub
          pointing at this path (mirroring the TS behavior).
        * Both ``None`` means the handler is genuinely unresolved
          (lambda, factory call, dynamic attr, etc.) — callers emit a
          plain unresolved stub so downstream consumers still see the
          capability was registered.
        """
        # Local lookup helpers ------------------------------------------------
        def _crossfile(name: str) -> Optional[str]:
            if cross_file_analyzer is None or not name:
                return None
            targets = (
                import_target_map.get(name) if import_target_map else None
            )
            try:
                match = self._resolve_cross_file_handler(
                    name,
                    cross_file_analyzer,
                    target_module_paths=targets,
                )
            except Exception:
                return None
            if match is None:
                return None
            return match[0]

        if isinstance(handler, ast.Name):
            local = functions_by_name.get(handler.id)
            if local is not None:
                return local, handler.id, None
            # Bare name missed in this file — try the cross-file graph.
            cross_file_path = _crossfile(handler.id)
            return None, handler.id, cross_file_path

        if isinstance(handler, ast.Attribute) and isinstance(
            handler.value, ast.Name
        ):
            base = handler.value.id
            attr = handler.attr
            if base in ("self", "cls") and enclosing_cls:
                node = class_methods.get(enclosing_cls, {}).get(attr)
                return node, f"{enclosing_cls}.{attr}", None
            # ``<module>.<name>`` — look up ``name`` in the call
            # graph, restricted to entries whose path lines up with
            # whatever ``<module>`` was bound to in this file's
            # imports. Without the import-map filter we'd suffix-match
            # any ``::<name>`` and possibly analyze the wrong file.
            target_paths: Optional[List[str]] = None
            if import_target_map:
                target_paths = import_target_map.get(base) or None
            cross_file_path: Optional[str] = None
            if cross_file_analyzer is not None and target_paths is not None:
                try:
                    match = self._resolve_cross_file_handler(
                        attr,
                        cross_file_analyzer,
                        target_module_paths=target_paths,
                    )
                except Exception:
                    match = None
                if match is not None:
                    cross_file_path = match[0]
            return None, f"{base}.{attr}", cross_file_path

        # Lambda, factory call, subscript, etc. — surface as unresolved
        # so the LLM still sees that something was registered here.
        return None, "<unresolved>", None
    def _py_iter_programmatic_registrations(
        self,
        tree: ast.AST,
        functions_by_name: Optional[
            Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]
        ] = None,
        class_methods: Optional[
            Dict[
                str,
                Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]],
            ]
        ] = None,
        *,
        cross_file_analyzer: Any = None,
        import_target_map: Optional[Dict[str, List[str]]] = None,
    ) -> List[
        "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str, str, Optional[str]]"
    ]:
        """Iterate programmatic / indirect MCP registration calls (Gap 8).

        Detects two complementary patterns:

        * **Direct programmatic registration** —
          ``<obj>.add_tool(fn)``, ``<obj>.register_resource(fn)`` and
          their kin. The first positional argument is taken as the
          handler reference.
        * **Decorator-factory applied to a bound method or function** —
          ``<obj>.tool(name='x')(self.do_thing)`` (the form used widely
          by AWS-Labs MCP servers) and the bare
          ``<obj>.tool(self.do_thing)`` shorthand. The decorator factory
          resolves to FastMCP shorthands (``tool``/``prompt``/
          ``resource`` and template variants) or the low-level
          ``Server`` decorators (``call_tool``/``list_tools``/
          ``read_resource``/``get_prompt``/etc.).

        Returns a list of
        ``(handler_node_or_None, label, capability, cross_file_path_or_None)``
        tuples.

        * ``handler_node`` non-None — local node, run dataflow on it.
        * ``handler_node`` None and ``cross_file_path`` non-None —
          handler resolved into another file via the call graph (Review
          #6); callers emit a ``registration.cross_file`` stub
          referencing that path.
        * Both None — genuinely unresolved (lambda, factory call,
          dynamic attribute, etc.); callers emit a plain unresolved
          stub so downstream consumers still see a registration.
        """
        functions_by_name = functions_by_name or {}
        class_methods = class_methods or {}

        out: List[
            "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str, str, Optional[str]]"
        ] = []

        for call, enclosing_cls in self._py_walk_calls_with_class_context(
            tree, []
        ):
            kind: Optional[str] = None
            handler_expr: Optional[ast.expr] = None

            method = self._py_call_method_name(call)
            if (
                method is not None
                and method in self._PY_PROGRAMMATIC_METHOD_TO_KIND
                and call.args
            ):
                kind = self._PY_PROGRAMMATIC_METHOD_TO_KIND[method]
                handler_expr = call.args[0]
            elif isinstance(call.func, ast.Call):
                # ``<obj>.tool(name='x')(handler)`` — decorator factory
                # applied to a function/method reference.
                inner_method = self._py_call_method_name(call.func)
                if (
                    inner_method is not None
                    and inner_method in self._PY_DECORATOR_FACTORY_METHOD_TO_KIND
                    and call.args
                ):
                    kind = self._PY_DECORATOR_FACTORY_METHOD_TO_KIND[
                        inner_method
                    ]
                    handler_expr = call.args[0]

            if kind is None or handler_expr is None:
                continue

            handler_node, label, cross_file_path = self._py_resolve_handler_expr(
                handler_expr,
                enclosing_cls,
                class_methods,
                functions_by_name,
                cross_file_analyzer=cross_file_analyzer,
                import_target_map=import_target_map,
            )
            out.append((handler_node, label, kind, cross_file_path))

        return out
    def _py_call_method_name(self, call: ast.Call) -> Optional[str]:
        """Return the dotted-leaf method name of an ``ast.Call``."""
        f = call.func
        if isinstance(f, ast.Attribute):
            return f.attr
        if isinstance(f, ast.Name):
            return f.id
        return None
    def _py_extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract all imports from Python AST.

        Reconstructs each import as a stable single-line string so the
        downstream regex-based collectors (e.g.
        ``_py_collect_import_targets``) can parse them uniformly.
        Relative imports preserve their leading dots — ``from .
        import handlers`` round-trips as ``"from . import handlers"``,
        not ``"from  import handlers"`` — so the import-target map can
        bind ``handlers`` to a path candidate, which the cross-file
        handler resolver needs for programmatic registrations like
        ``mcp.tool(name='x')(handlers.do_thing)``.
        """
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    stmt = f"import {alias.name}"
                    if alias.asname:
                        stmt += f" as {alias.asname}"
                    imports.append(stmt)
            elif isinstance(node, ast.ImportFrom):
                # Preserve the relative-import dot prefix from
                # ``node.level``. Without this, ``from . import x`` and
                # ``from ..pkg import x`` collapse to bare ``from
                # import x`` / ``from pkg import x`` respectively, both
                # of which fail the ``^from\s+(\S+)\s+import\s+...``
                # regex that the import-target collector uses to bind
                # names to module paths.
                level = node.level or 0
                module = ("." * level) + (node.module or "")
                for alias in node.names:
                    stmt = f"from {module} import {alias.name}"
                    if alias.asname:
                        stmt += f" as {alias.asname}"
                    imports.append(stmt)
        return imports
    def _py_collect_decorators(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
        """Decorator names and the keyword arguments each was called with."""
        decorator_types = []
        decorator_params: Dict[str, Dict[str, Any]] = {}
        for dec in node.decorator_list:
            dec_name = self._py_get_node_name(dec)
            decorator_types.append(dec_name)
            if isinstance(dec, ast.Call):
                dec_params = self._py_extract_call_kwargs(dec)
                if dec_params:
                    decorator_params[dec_name] = dec_params

        return decorator_types, decorator_params

    @staticmethod
    def _py_apply_decorator_overrides(
        decorator_params: Dict[str, Dict[str, Any]],
        name: str,
        docstring: Optional[str],
    ) -> Tuple[str, Optional[str]]:
        """Let ``@tool(name=..., description=...)`` override the Python names.

        The decorator's name is what the MCP client sees, so it wins over the
        function's. The description only fills in for a missing docstring.
        """
        for _dec_name, params in decorator_params.items():
            if "name" in params:
                raw_name = params["name"]
                if isinstance(raw_name, str):
                    try:
                        name = ast.literal_eval(raw_name)
                    except (ValueError, SyntaxError):
                        name = raw_name
                else:
                    name = raw_name
            if "description" in params and not docstring:
                raw_desc = params["description"]
                if isinstance(raw_desc, str):
                    try:
                        docstring = ast.literal_eval(raw_desc)
                    except (ValueError, SyntaxError):
                        docstring = raw_desc
                else:
                    docstring = raw_desc

        return name, docstring

    def _py_collect_parameters(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parameter descriptors plus their bare names for dataflow analysis."""
        parameters = []
        param_names = []
        for arg in node.args.args:
            param_info: Dict[str, Any] = {"name": arg.arg}
            if arg.annotation:
                param_info["type"] = self._py_unparse_safe(arg.annotation)
            parameters.append(param_info)
            param_names.append(arg.arg)

        return parameters, param_names

    def _py_collect_function_calls(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[Dict[str, Any]]:
        """Every call made anywhere in the function body."""
        function_calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                function_calls.append({
                    "name": self._py_get_node_name(child.func),
                    "args": [self._py_unparse_safe(a) for a in child.args],
                    "kwargs": {kw.arg: self._py_unparse_safe(kw.value) for kw in child.keywords if kw.arg},
                    "line": getattr(child, "lineno", 0),
                })

        return function_calls

    def _py_collect_assignments(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[Dict[str, Any]]:
        """Plain, annotated and augmented assignments, in one list."""
        assignments = []
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    assignments.append({
                        "target": self._py_unparse_safe(target),
                        "value": self._py_unparse_safe(child.value),
                        "line": getattr(child, "lineno", 0),
                    })
            elif isinstance(child, ast.AnnAssign):
                assignments.append({
                    "target": self._py_unparse_safe(child.target),
                    "annotation": self._py_unparse_safe(child.annotation),
                    "value": self._py_unparse_safe(child.value) if child.value else None,
                    "line": getattr(child, "lineno", 0),
                })
            elif isinstance(child, ast.AugAssign):
                assignments.append({
                    "target": self._py_unparse_safe(child.target),
                    "op": child.op.__class__.__name__,
                    "value": self._py_unparse_safe(child.value),
                    "line": getattr(child, "lineno", 0),
                })

        return assignments

    def _py_collect_control_flow(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Dict[str, Any]:
        """Branch, loop, try and with statements, grouped by kind."""
        control_flow = {
            "if_statements": [{"line": n.lineno, "test": self._py_unparse_safe(n.test)}
                             for n in ast.walk(node) if isinstance(n, ast.If)],
            "for_loops": [{"line": n.lineno, "target": self._py_unparse_safe(n.target),
                          "iter": self._py_unparse_safe(n.iter)}
                         for n in ast.walk(node) if isinstance(n, (ast.For, ast.AsyncFor))],
            "while_loops": [{"line": n.lineno, "test": self._py_unparse_safe(n.test)}
                           for n in ast.walk(node) if isinstance(n, ast.While)],
            "try_blocks": [{"line": n.lineno} for n in ast.walk(node) if isinstance(n, ast.Try)],
            "with_statements": [{"line": n.lineno, "items": [self._py_unparse_safe(i.context_expr) for i in n.items]}
                               for n in ast.walk(node) if isinstance(n, (ast.With, ast.AsyncWith))],
        }

        return control_flow

    @staticmethod
    def _py_collect_constants(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Dict[str, Any]:
        """Names bound directly to a literal."""
        constants: Dict[str, Any] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and isinstance(child.value, ast.Constant):
                        constants[target.id] = child.value.value

        return constants

    @staticmethod
    def _py_collect_variable_dependencies(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Dict[str, List[str]]:
        """For each assigned name, the names its value reads."""
        var_deps: Dict[str, List[str]] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        deps = [n.id for n in ast.walk(child.value) if isinstance(n, ast.Name)]
                        var_deps[target.id] = deps

        return var_deps

    @staticmethod
    def _py_collect_string_literals(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[str]:
        """Distinct short string literals, capped at 50."""
        string_literals = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if child.value and len(child.value) <= 500:
                    string_literals.append(child.value)
        string_literals = list(set(string_literals))[:50]

        return string_literals

    def _py_collect_return_expressions(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[str]:
        """The expression behind every ``return`` that has one."""
        return_expressions = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                return_expressions.append(self._py_unparse_safe(child.value))

        return return_expressions

    def _py_collect_exception_handlers(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[Dict[str, Any]]:
        """Except clauses, with the size of each handler body."""
        exception_handlers = []
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                exception_handlers.append({
                    "line": child.lineno,
                    "type": self._py_unparse_safe(child.type) if child.type else "Exception",
                    "name": child.name,
                    "body_size": len(child.body),
                })

        return exception_handlers

    @staticmethod
    def _py_collect_global_writes(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[Dict[str, Any]]:
        """``global`` and ``nonlocal`` declarations."""
        global_writes = []
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                for name in child.names:
                    global_writes.append({"type": "global", "name": name, "line": child.lineno})
            elif isinstance(child, ast.Nonlocal):
                for name in child.names:
                    global_writes.append({"type": "nonlocal", "name": name, "line": child.lineno})

        return global_writes

    def _py_collect_attribute_access(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[Dict[str, Any]]:
        """Attribute reads and writes, capped at 50."""
        attribute_access = []
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                attribute_access.append({
                    "object": self._py_unparse_safe(child.value),
                    "attr": child.attr,
                    "line": getattr(child, "lineno", 0),
                })
        attribute_access = attribute_access[:50]

        return attribute_access

    def _py_collect_subscript_access(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[Dict[str, Any]]:
        """Subscript expressions such as ``d[k]``."""
        subscript_access = []
        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                subscript_access.append({
                    "value": self._py_unparse_safe(child.value),
                    "slice": self._py_unparse_safe(child.slice),
                    "line": getattr(child, "lineno", 0),
                })

        return subscript_access

    @staticmethod
    def _py_cyclomatic_complexity(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> int:
        """Branch count plus one -- the usual cyclomatic measure."""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

        return complexity

    def _py_extract_function(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], module_imports: List[str]
    ) -> FunctionContext:
        """Extract FunctionContext from Python function AST node with full dataflow analysis.

        Uses the existing ForwardDataflowAnalysis infrastructure for proper
        CFG-based taint tracking with shape-aware analysis.
        """
        decorator_types, decorator_params = self._py_collect_decorators(node)
        name, docstring = self._py_apply_decorator_overrides(
            decorator_params, node.name, ast.get_docstring(node)
        )
        parameters, param_names = self._py_collect_parameters(node)

        # Use existing ForwardDataflowAnalysis for proper CFG-based taint tracking
        parameter_flows = self._py_analyze_dataflow_full(node, param_names)

        # Detect security operations via dataflow
        security_ops = self._py_detect_security_ops(node)

        subscript_access = self._py_collect_subscript_access(node)

        # Build dataflow summary with taint info
        dataflow_summary = {
            "total_statements": len([n for n in ast.walk(node) if isinstance(n, ast.stmt)]),
            "total_expressions": len([n for n in ast.walk(node) if isinstance(n, ast.expr)]),
            "complexity": self._py_cyclomatic_complexity(node),
            "subscript_access": subscript_access[:20],
            "param_flows": {p["parameter_name"]: {
                "reaches_calls": p.get("reaches_calls", []),
                "reaches_returns": p.get("reaches_returns", False),
                "reaches_external": p.get("reaches_external", False),
            } for p in parameter_flows},
        }

        # Build FunctionContext with dataflow analysis results
        return FunctionContext(
            name=name,
            decorator_types=decorator_types,
            decorator_params=decorator_params,
            docstring=docstring,
            parameters=parameters,
            return_type=self._py_unparse_safe(node.returns) if node.returns else None,
            line_number=node.lineno,
            imports=module_imports,
            function_calls=self._py_collect_function_calls(node),
            assignments=self._py_collect_assignments(node),
            control_flow=self._py_collect_control_flow(node),
            parameter_flows=parameter_flows,  # Already list of dicts
            constants=self._py_collect_constants(node),
            variable_dependencies=self._py_collect_variable_dependencies(node),
            has_file_operations=security_ops["has_file_operations"],
            has_network_operations=security_ops["has_network_operations"],
            has_subprocess_calls=security_ops["has_subprocess_calls"],
            has_eval_exec=security_ops["has_eval_exec"],
            has_dangerous_imports=any(d in " ".join(module_imports) for d in ["subprocess", "os", "pickle", "marshal"]),
            dataflow_summary=dataflow_summary,
            string_literals=self._py_collect_string_literals(node),
            return_expressions=self._py_collect_return_expressions(node),
            exception_handlers=self._py_collect_exception_handlers(node),
            env_var_access=[],
            global_writes=self._py_collect_global_writes(node),
            attribute_access=self._py_collect_attribute_access(node),
        )

    def _py_get_node_name(self, node: ast.expr) -> str:
        """Get name from any AST expression node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        elif isinstance(node, ast.Call):
            return self._py_get_node_name(node.func)
        else:
            return self._py_unparse_safe(node)
    def _py_extract_call_kwargs(self, call: ast.Call) -> Dict[str, Any]:
        """Extract keyword arguments from a call node."""
        kwargs: Dict[str, Any] = {}
        for kw in call.keywords:
            if kw.arg:
                kwargs[kw.arg] = self._py_unparse_safe(kw.value)
        return kwargs
    def _py_unparse_safe(self, node: Optional[ast.AST]) -> str:
        """Safely unparse an AST node to string."""
        if node is None:
            return ""
        try:
            return ast.unparse(node)
        except Exception:
            return f"<{node.__class__.__name__}>"
    def _py_analyze_dataflow_full(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], param_names: List[str]
    ) -> List[Dict[str, Any]]:
        """Perform full dataflow analysis using existing ForwardDataflowAnalysis.
        
        This leverages the CFG-based taint tracking infrastructure from
        mcpscanner.core.static_analysis.dataflow and taint modules.
        """
        try:
            # Create a function-specific source for the parser
            func_source = ast.unparse(node)
            func_parser = PythonParser(func_source)
            func_parser.parse()
            
            # Use ForwardDataflowAnalysis for proper CFG-based analysis
            tracker = ForwardDataflowAnalysis(func_parser, param_names)
            flows = tracker.analyze_forward_flows()
            
            # Convert FlowPath objects to dicts for FunctionContext
            return [{
                "parameter_name": flow.parameter_name,
                "operations": flow.operations,
                "reaches_calls": flow.reaches_calls,
                "reaches_assignments": flow.reaches_assignments,
                "reaches_returns": flow.reaches_returns,
                "reaches_external": flow.reaches_external,
            } for flow in flows]
        except Exception as e:
            self.logger.debug(f"Full dataflow analysis failed, using simple analysis: {e}")
            # Fallback to simple analysis
            return self._py_analyze_dataflow_simple(node, param_names)
    def _py_analyze_dataflow_simple(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], param_names: List[str]
    ) -> List[Dict[str, Any]]:
        """Simple dataflow analysis fallback when full analysis fails."""
        # Reset taint environment
        self._taint_env = {}
        for pname in param_names:
            self._taint_env[pname] = TaintInfo(status=TaintStatus.TAINTED, sources={pname})
        
        flows = {name: {"parameter_name": name, "operations": [], "reaches_calls": [], 
                       "reaches_assignments": [], "reaches_returns": False, "reaches_external": False} 
                for name in param_names}
        
        external_patterns = {"open", "read", "write", "requests", "urllib", "subprocess", "os.system", "eval", "exec"}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                rhs_taint = self._py_eval_taint(child.value)
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        self._taint_env[target.id] = rhs_taint
                        if rhs_taint.is_tainted():
                            for param in param_names:
                                if param in rhs_taint.sources:
                                    flows[param]["reaches_assignments"].append(target.id)
            
            elif isinstance(child, ast.Call):
                call_name = self._py_get_node_name(child.func)
                for arg in child.args:
                    arg_taint = self._py_eval_taint(arg)
                    if arg_taint.is_tainted():
                        for param in param_names:
                            if param in arg_taint.sources:
                                flows[param]["reaches_calls"].append(call_name)
                                if any(p in call_name for p in external_patterns):
                                    flows[param]["reaches_external"] = True
            
            elif isinstance(child, ast.Return) and child.value:
                ret_taint = self._py_eval_taint(child.value)
                if ret_taint.is_tainted():
                    for param in param_names:
                        if param in ret_taint.sources:
                            flows[param]["reaches_returns"] = True
        
        return list(flows.values())
    def _py_eval_taint(self, expr: ast.AST) -> TaintInfo:
        """Evaluate taint of a Python expression."""
        if isinstance(expr, ast.Name):
            return self._taint_env.get(expr.id, TaintInfo())
        elif isinstance(expr, ast.Attribute):
            return self._py_eval_taint(expr.value)
        elif isinstance(expr, ast.Subscript):
            return self._py_eval_taint(expr.value)
        elif isinstance(expr, ast.Call):
            result = TaintInfo()
            for arg in expr.args:
                result = result.merge(self._py_eval_taint(arg))
            for kw in expr.keywords:
                result = result.merge(self._py_eval_taint(kw.value))
            return result
        elif isinstance(expr, ast.BinOp):
            left = self._py_eval_taint(expr.left)
            right = self._py_eval_taint(expr.right)
            return left.merge(right)
        elif isinstance(expr, ast.JoinedStr):
            result = TaintInfo()
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    result = result.merge(self._py_eval_taint(value.value))
            return result
        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            result = TaintInfo()
            for elt in expr.elts:
                result = result.merge(self._py_eval_taint(elt))
            return result
        elif isinstance(expr, ast.Dict):
            result = TaintInfo()
            for v in expr.values:
                if v:
                    result = result.merge(self._py_eval_taint(v))
            return result
        return TaintInfo()
    def _py_detect_security_ops(self, node: ast.AST) -> Dict[str, bool]:
        """Detect security-relevant operations via dataflow analysis."""
        has_file = False
        has_network = False
        has_subprocess = False
        has_eval = False
        
        file_patterns = {"open", "read", "write", "close", "os.remove", "os.unlink", "shutil", "pathlib"}
        network_patterns = {"requests", "urllib", "http", "httpx", "aiohttp", "socket"}
        subprocess_patterns = {"subprocess", "os.system", "os.popen", "os.exec"}
        eval_patterns = {"eval", "exec", "compile", "__import__"}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._py_get_node_name(child.func)
                
                if any(p in call_name for p in file_patterns):
                    has_file = True
                if any(p in call_name for p in network_patterns):
                    has_network = True
                if any(p in call_name for p in subprocess_patterns):
                    has_subprocess = True
                if call_name in eval_patterns:
                    has_eval = True
        
        return {
            "has_file_operations": has_file,
            "has_network_operations": has_network,
            "has_subprocess_calls": has_subprocess,
            "has_eval_exec": has_eval,
        }
