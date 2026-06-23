# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""C# MCP capability adapter.

C# uses [attribute] syntax for capability registration. The official
.NET MCP SDK ships ``[McpServerTool]`` / ``[McpServerPrompt]`` /
``[McpServerResource]`` and the broader ``ModelContextProtocol`` /
``ModelContextProtocol.Server`` namespaces; bare ``[Tool]`` only
classifies as MCP when one of those namespaces is in scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, FrozenSet, Optional

from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


class CSharpAdapter(AdapterMixin):
    """Adapter for C# sources using the official .NET MCP SDK."""

    LANGUAGE = "c_sharp"
    SDK_MODULE_PREFIXES = ("modelcontextprotocol",)
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset(
        {"", "ModelContextProtocol", "ModelContextProtocol.Server"}
    )
    ANNOTATION_IDENTIFIERS = {
        # .NET MCP SDK attributes
        "McpServerTool": "tool",
        "McpServerPrompt": "prompt",
        "McpServerResource": "resource",
        "McpServerToolType": "tool",
        # Generic forms only accepted via trusted namespace check
        "Tool": "tool",
        "Prompt": "prompt",
        "Resource": "resource",
    }

    def tree_sitter_language(self) -> Optional["Language"]:
        from tree_sitter import Language

        from ..native_analyzer import _get_language_module

        lang_mod = _get_language_module(self.LANGUAGE)
        if lang_mod is None:
            return None
        return Language(lang_mod.language())


ADAPTER = CSharpAdapter()

__all__ = ["CSharpAdapter", "ADAPTER"]
