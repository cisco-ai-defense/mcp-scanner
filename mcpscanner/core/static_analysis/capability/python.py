# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Python MCP capability adapter.

Python is the **outlier** among supported languages: detection runs
through the standard library's ``ast`` module rather than tree-sitter.
The adapter therefore returns ``None`` from :py:meth:`tree_sitter_language`
and the orchestrator routes Python files to a dedicated entry point
(``_py_extract_capability_contexts`` on :class:`CapabilityDetector`).

This adapter contributes:

* The SDK module prefixes used by the Stage-1 instance collector
  (``fastmcp``, ``mcp.server``, ``mcp.types``, ``modelcontextprotocol``).
* The Stage-1 import-alias hook that scans
  ``from fastmcp import FastMCP`` / ``from mcp.server import Server``
  to populate the trusted-class set.
* The cross-file import-target parser used by the handler resolver to
  map ``from .tools.add import addHandler`` to the correct path
  candidates.
* The annotation-identifier mapping used when tree-sitter-style
  annotation text is fed back through the shared classifier (e.g.
  ``@server.tool`` decorators captured by the Python AST walker that
  ultimately go through the same kind-classification helper).

The big ``_py_*`` helper methods on :class:`CapabilityDetector` stay
where they are — they're already a self-contained Python pipeline
(decorator analysis, programmatic registration, handler resolution)
and don't have ``if self.language == "python"`` branches *inside* them.
The entry-point branch in ``extract_mcp_capability_contexts`` is the
one actual conditional, and it's now driven by
:py:meth:`tree_sitter_language` returning ``None`` rather than a
language-equality check.
"""

from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, List, Optional, Set

from .base import AdapterMixin


_PY_FROM_IMPORT_RE = re.compile(
    r"^from\s+(\S+)\s+import\s+(.+?)\s*$",
)
_PY_IMPORT_RE = re.compile(
    r"^import\s+([\w\.]+)(?:\s+as\s+(\w+))?\s*$",
)
_PY_FROM_SDK_IMPORT_RE = re.compile(
    r"\s*from\s+([\w\.]+)\s+import\s+([\w\s,]+)",
)


class PythonAdapter(AdapterMixin):
    """Adapter for Python sources using fastmcp / official MCP SDK."""

    LANGUAGE = "python"
    SDK_MODULE_PREFIXES = (
        "fastmcp",
        "mcp.server",
        "mcp.types",
        "modelcontextprotocol",
    )
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset({""})
    ANNOTATION_IDENTIFIERS = {
        # Used by the Python branch when a tree-sitter style annotation
        # text (``@<obj>.tool``) is fed back through the same classifier.
        "tool": "tool",
        "prompt": "prompt",
        "resource": "resource",
        # Low-level server decorators
        "call_tool": "tool",
        "list_tools": "tool",
        "get_prompt": "prompt",
        "list_prompts": "prompt",
        "read_resource": "resource",
        "list_resources": "resource",
        "list_resource_templates": "resource",
    }

    def parse_import_alias(
        self,
        stmt: str,
        sdk_classes: Set[str],
        sdk_aliases: Set[str],
    ) -> None:
        # ``from fastmcp import FastMCP`` /
        # ``from mcp.server import Server`` — collect imported symbols
        # so the Stage-2 walker recognizes constructions like
        # ``FastMCP("demo")`` as MCP instances.
        m = _PY_FROM_SDK_IMPORT_RE.match(stmt)
        if m:
            for sym in m.group(2).split(","):
                sym = sym.strip().split(" as ")[0].strip()
                if sym:
                    sdk_classes.add(sym)

    def parse_import_target(
        self,
        stmt: str,
        out: Dict[str, List[str]],
    ) -> None:
        # ``from <module> import X [as Y], ...``
        m = _PY_FROM_IMPORT_RE.match(stmt)
        if m:
            from ..capability_detector import _normalize_module_specifier

            module = _normalize_module_specifier(m.group(1))
            for piece in m.group(2).split(","):
                piece = piece.strip().rstrip(")").lstrip("(")
                if not piece or piece == "*":
                    continue
                parts = re.split(r"\s+as\s+", piece, maxsplit=1)
                orig = parts[0].strip()
                bound = parts[1].strip() if len(parts) > 1 else orig
                if not bound:
                    continue
                # ``orig`` could either be a function within ``module``
                # or a submodule of ``module`` (when used like
                # ``from .tools import docs`` to bind a module). Record
                # both candidates so the resolver picks whichever
                # actually exists in the call graph.
                if module:
                    out.setdefault(bound, []).append(module)
                    out[bound].append(f"{module}/{orig}")
                else:
                    out.setdefault(bound, []).append(orig)
            return
        # ``import M [as N]`` or ``import M.sub``
        m = _PY_IMPORT_RE.match(stmt)
        if m:
            full = m.group(1)
            alias = m.group(2)
            bound = alias or full.split(".", 1)[0]
            if bound:
                out.setdefault(bound, []).append(full)

    def tree_sitter_language(self) -> Optional[object]:
        # Python detection bypasses tree-sitter entirely (uses ``ast``),
        # so the orchestrator gets ``None`` here and routes to the
        # dedicated Python pipeline via :py:meth:`extract_with_native_parser`.
        return None

    def extract_with_native_parser(
        self,
        detector: Any,
        cross_file_analyzer: Optional[Any] = None,
    ) -> Optional[List[Any]]:
        # Delegate to the AST-based pipeline that already lives on
        # :class:`CapabilityDetector`. Returning the list (instead of
        # ``None``) signals to the orchestrator that detection is
        # complete and the generic tree-sitter walker should be
        # skipped.
        return detector._py_extract_capability_contexts(
            cross_file_analyzer=cross_file_analyzer
        )


ADAPTER = PythonAdapter()

__all__ = ["PythonAdapter", "ADAPTER"]
