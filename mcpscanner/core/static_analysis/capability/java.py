# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Java MCP capability adapter.

Java detection is **annotation-driven**: handlers are functions
annotated with ``@Tool`` / ``@McpTool`` / ``@McpResource`` /
``@McpPrompt`` (Spring AI MCP and the official Java SDK). There are no
``server.addTool(...)`` style programmatic registrations to walk, so
this adapter is mostly data:

* The Spring AI namespace (``org.springframework.ai``) and the
  official ``io.modelcontextprotocol`` namespace are both trusted —
  bare ``@Tool`` resolves to MCP only when one of those is in scope.
* Annotation aliases like ``@McpTool`` always classify, regardless of
  namespace.

The shared registration / annotation walker in
:mod:`capability_detector` reads :data:`ANNOTATION_IDENTIFIERS` and
:data:`TRUSTED_NAMESPACES` directly via :py:func:`get_adapter`, so this
module owns the source of truth for the Java SDK shape.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, FrozenSet, Optional

from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


class JavaAdapter(AdapterMixin):
    """Adapter for Java sources using Spring AI MCP / official MCP SDK."""

    LANGUAGE = "java"
    SDK_MODULE_PREFIXES = (
        "io.modelcontextprotocol",
        "org.springframework.ai",
    )
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset(
        {"", "org.springframework.ai", "io.modelcontextprotocol"}
    )
    ANNOTATION_IDENTIFIERS = {
        # Spring AI MCP annotations
        "Tool": "tool",
        "McpTool": "tool",
        "ToolParam": "tool",
        "McpResource": "resource",
        "Resource": "resource",
        "McpPrompt": "prompt",
        "Prompt": "prompt",
    }

    def tree_sitter_language(self) -> Optional["Language"]:
        # Lazy import — keeps the adapter cheap to import for callers
        # that never scan a Java file. The factory is only invoked
        # once per scanner process, then cached by ``CapabilityDetector``.
        from tree_sitter import Language

        from ..native_analyzer import _get_language_module

        lang_mod = _get_language_module(self.LANGUAGE)
        if lang_mod is None:
            return None
        return Language(lang_mod.language())


ADAPTER = JavaAdapter()

__all__ = ["JavaAdapter", "ADAPTER"]
