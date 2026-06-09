# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Rust MCP capability adapter.

Rust detection is macro-driven via the rmcp crate's ``#[tool]`` /
``#[prompt]`` / ``#[resource]`` attribute macros. The shared
function-collector intentionally walks *into* ``impl_item`` blocks
(handlers live there) but doesn't classify the impl block itself —
that filtering happens in the generic walker via the
``_TS_NON_FUNCTION_NODE_TYPES`` guard, not here.

``tool_router`` and ``tool_handler`` are intentionally absent from
:data:`ANNOTATION_IDENTIFIERS`: they mark the *router* / *dispatch*
impl block, not individual tool callables. The capability extractor
recurses into the impl and matches the per-method ``#[tool]`` macros.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, FrozenSet, Optional

from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


class RustAdapter(AdapterMixin):
    """Adapter for Rust sources using the rmcp crate."""

    LANGUAGE = "rust"
    SDK_MODULE_PREFIXES = (
        "rmcp",
        "modelcontextprotocol",
    )
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset({"", "rmcp", "mcp"})
    ANNOTATION_IDENTIFIERS = {
        # rmcp attribute macros
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


ADAPTER = RustAdapter()

__all__ = ["RustAdapter", "ADAPTER"]
