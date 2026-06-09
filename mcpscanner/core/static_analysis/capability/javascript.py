# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""JavaScript MCP capability adapter.

JavaScript shares the official ``@modelcontextprotocol/sdk`` SDK with
TypeScript, but the two are intentionally **siblings** rather than
parent/child: the grammar quirks they care about (TS-only type-only
imports, JSX attribute syntax, etc.) shouldn't propagate across the
boundary. They share the import-target parser via
:mod:`._ts_imports` (composition over inheritance).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, FrozenSet, List, Optional

from . import _ts_imports
from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


class JavaScriptAdapter(AdapterMixin):
    """Adapter for JavaScript sources using the official MCP TS SDK."""

    LANGUAGE = "javascript"
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
        _ts_imports.collect_import_targets(stmt, out)

    def tree_sitter_language(self) -> Optional["Language"]:
        from tree_sitter import Language

        from ..native_analyzer import _get_language_module

        lang_mod = _get_language_module(self.LANGUAGE)
        if lang_mod is None:
            return None
        return Language(lang_mod.language())


ADAPTER = JavaScriptAdapter()

__all__ = ["JavaScriptAdapter", "ADAPTER"]
