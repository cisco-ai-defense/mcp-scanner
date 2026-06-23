# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""PHP MCP capability adapter.

PHP detection is annotation-driven via the php-mcp/server attribute
shapes (``#[Tool]`` / ``#[McpTool]`` / ``#[Prompt]`` / ``#[Resource]``).
The PHP namespace separator is ``\\`` rather than ``.``; that's
already handled by the generic ``_split_annotation_namespace`` helper
in :mod:`capability_detector`, so this adapter just lists the trusted
namespaces in their PHP form.

The PHP tree-sitter grammar exposes a different module-level factory
function (``language_php()`` rather than ``language()``); the override
in :py:meth:`tree_sitter_language` reflects that.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, FrozenSet, Optional

from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


class PhpAdapter(AdapterMixin):
    """Adapter for PHP sources using php-mcp/server."""

    LANGUAGE = "php"
    SDK_MODULE_PREFIXES = (
        "phpmcp",
        "modelcontextprotocol",
    )
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset(
        {"", "PhpMcp", "PhpMcp\\Server", "PhpMcp\\Server\\Attributes"}
    )
    ANNOTATION_IDENTIFIERS = {
        # php-mcp/server attributes
        "Tool": "tool",
        "McpTool": "tool",
        "Prompt": "prompt",
        "McpPrompt": "prompt",
        "Resource": "resource",
        "McpResource": "resource",
    }

    def tree_sitter_language(self) -> Optional["Language"]:
        from tree_sitter import Language

        from ..native_analyzer import _get_language_module

        lang_mod = _get_language_module(self.LANGUAGE)
        if lang_mod is None:
            return None
        # PHP grammar exposes ``language_php()`` rather than the
        # generic ``language()`` factory other grammars use.
        return Language(lang_mod.language_php())


ADAPTER = PhpAdapter()

__all__ = ["PhpAdapter", "ADAPTER"]
