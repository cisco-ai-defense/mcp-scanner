# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Kotlin MCP capability adapter.

The Kotlin SDK uses ``server.addTool(...) { req -> ... }`` with the
trailing-lambda shape; the registration walker in
:mod:`capability_detector` already handles the lambda recovery (both
the embedded-in-call_expression and parent-sibling forms across
tree-sitter-kotlin grammar versions).

This adapter contributes:

* The SDK module prefix (``io.modelcontextprotocol``) used by Stage 1
  of the instance collector.
* The Stage-1 import-alias hook that picks up class names imported
  from the SDK package (``import io.modelcontextprotocol.kotlin.sdk.server.Server``
  exposes ``Server`` as a known SDK class so subsequent
  ``val s = Server()`` constructions are flagged as MCP instances).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, FrozenSet, Optional, Set

from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


_KOTLIN_TRAILING_IDENT_RE = re.compile(r"\.(\w+)\s*$")


class KotlinAdapter(AdapterMixin):
    """Adapter for Kotlin sources using the official MCP Kotlin SDK."""

    LANGUAGE = "kotlin"
    SDK_MODULE_PREFIXES = ("io.modelcontextprotocol",)
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset({""})
    ANNOTATION_IDENTIFIERS: Dict[str, str] = {}

    def parse_import_alias(
        self,
        stmt: str,
        sdk_classes: Set[str],
        sdk_aliases: Set[str],
    ) -> None:
        # ``import io.modelcontextprotocol.kotlin.sdk.server.Server`` →
        # binds the trailing identifier (``Server``) into the local
        # namespace. Subsequent ``val s = Server()`` constructions are
        # then recognized as MCP instantiations.
        m = _KOTLIN_TRAILING_IDENT_RE.search(stmt)
        if m:
            sdk_classes.add(m.group(1))

    def tree_sitter_language(self) -> Optional["Language"]:
        from tree_sitter import Language

        from ..native_analyzer import _get_language_module

        lang_mod = _get_language_module(self.LANGUAGE)
        if lang_mod is None:
            return None
        return Language(lang_mod.language())


ADAPTER = KotlinAdapter()

__all__ = ["KotlinAdapter", "ADAPTER"]
