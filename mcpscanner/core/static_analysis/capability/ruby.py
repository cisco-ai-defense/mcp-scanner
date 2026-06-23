# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Ruby MCP capability adapter.

Ruby SDKs (mcp-rb / community libraries) use comment-style annotations
above method definitions (``# @tool name: ...``). Identifiers are
lower-case by convention; the generic annotation collector lowercases
incoming text before consulting :data:`ANNOTATION_IDENTIFIERS`, so we
list them in lower-case here too.

There are no programmatic ``server.add_tool(...)`` registrations in
the Ruby SDK shape, so this adapter is data-only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, FrozenSet, Optional

from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


class RubyAdapter(AdapterMixin):
    """Adapter for Ruby sources using mcp-rb / community SDKs."""

    LANGUAGE = "ruby"
    SDK_MODULE_PREFIXES = ("mcp",)
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset({""})
    ANNOTATION_IDENTIFIERS = {
        "tool": "tool",
        "prompt": "prompt",
        "resource": "resource",
    }

    def tree_sitter_language(self) -> Optional["Language"]:
        from tree_sitter import Language

        from ..native_analyzer import _get_language_module

        lang_mod = _get_language_module(self.LANGUAGE)
        if lang_mod is None:
            return None
        return Language(lang_mod.language())


ADAPTER = RubyAdapter()

__all__ = ["RubyAdapter", "ADAPTER"]
