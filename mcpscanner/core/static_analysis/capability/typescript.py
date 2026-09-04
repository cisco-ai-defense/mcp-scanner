# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""TypeScript MCP capability adapter.

TypeScript uses the official ``@modelcontextprotocol/sdk`` package
(both the ``typescript-sdk`` alias and the bare ``@modelcontextprotocol/sdk``
prefix are accepted). Detection runs through the shared tree-sitter
walker:

* High-level ``server.registerTool(...)`` / ``registerPrompt(...)`` /
  ``registerResource(...)`` calls;
* Low-level ``server.setRequestHandler(SchemaSymbol, handler)`` calls
  (Schema -> capability mapping lives in :mod:`capability_detector`'s
  ``_LOW_LEVEL_SCHEMA_TO_CAPABILITY``).

Annotations aren't part of the official TS SDK shape but
``ANNOTATION_IDENTIFIERS`` is empty rather than absent so the generic
annotation collector can consult it without a separate "is this
language annotation-driven?" check.

The TS grammar exposes a different module-level factory function
(``language_typescript()`` rather than ``language()``); the override
in :py:meth:`tree_sitter_language` reflects that.

The :py:meth:`parse_import_target` override delegates to the
:mod:`._ts_imports` helper so JavaScript and TypeScript share the same
import-grammar parser without one subclassing the other.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, FrozenSet, List, Optional

from . import _ts_imports
from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


class TypeScriptAdapter(AdapterMixin):
    """Adapter for TypeScript sources using the official MCP TS SDK."""

    LANGUAGE = "typescript"
    SDK_MODULE_PREFIXES = (
        "@modelcontextprotocol/sdk",
        "@modelcontextprotocol/typescript-sdk",
    )
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset({""})
    ANNOTATION_IDENTIFIERS: Dict[str, str] = {}

    def parse_import_target(
        self,
        stmt: str,
        out: Dict[str, List[str]],
    ) -> None:
        # JS and TS share an import grammar (TS adds type-only imports
        # but they're a strict subset for our purposes); the parser
        # lives in ``_ts_imports`` so neither language subclasses the
        # other.
        _ts_imports.collect_import_targets(stmt, out)

    def tree_sitter_language(self) -> Optional["Language"]:
        from tree_sitter import Language

        from ..native_analyzer import _get_language_module

        lang_mod = _get_language_module(self.LANGUAGE)
        if lang_mod is None:
            return None
        # TS grammar exposes ``language_typescript()`` rather than the
        # generic ``language()`` factory other grammars use.
        return Language(lang_mod.language_typescript())


ADAPTER = TypeScriptAdapter()

__all__ = ["TypeScriptAdapter", "ADAPTER"]
