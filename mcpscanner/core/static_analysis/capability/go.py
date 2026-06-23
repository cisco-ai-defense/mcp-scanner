# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Go MCP capability adapter.

The Go SDK (``github.com/modelcontextprotocol/go-sdk/mcp``) uses a
top-level ``mcp.AddTool(server, &mcp.Tool{...}, handler)`` shape where
the *first* argument is the server instance, not the receiver. The
generic registration walker in :mod:`capability_detector` reads
:data:`SDK_MODULE_PREFIXES` to filter imports and threads the
``parse_import_alias`` hook below to register the SDK alias the user
imported the package as (``import "github.com/...mcp"`` exposes ``mcp``;
``import alias "..."`` exposes ``alias``).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, FrozenSet, List, Optional, Set

from .base import AdapterMixin

if TYPE_CHECKING:
    from tree_sitter import Language


_GO_SDK_IMPORT_RE = re.compile(
    r'^\s*(?:import\s+)?(?:([\w]+)\s+)?"[^"]*modelcontextprotocol[^"]*"'
)
_GO_IMPORT_TARGET_RE = re.compile(
    r"""(?:^|\b)(?:import\s+)?(?:(\w+)\s+)?['"]([^'"]+)['"]"""
)


class GoAdapter(AdapterMixin):
    """Adapter for Go sources using the official MCP Go SDK."""

    LANGUAGE = "go"
    SDK_MODULE_PREFIXES = (
        "modelcontextprotocol/go-sdk",
        "modelcontextprotocol/go-sdk/mcp",
    )
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset({""})
    ANNOTATION_IDENTIFIERS: Dict[str, str] = {}

    def parse_import_alias(
        self,
        stmt: str,
        sdk_classes: Set[str],
        sdk_aliases: Set[str],
    ) -> None:
        # ``import "...github.com/modelcontextprotocol/go-sdk/mcp"`` →
        # exposes ``mcp`` as the package alias; ``import alias "..."``
        # rebinds it.
        m = _GO_SDK_IMPORT_RE.search(stmt)
        if m:
            sdk_aliases.add(m.group(1) or "mcp")

    def parse_import_target(
        self,
        stmt: str,
        out: Dict[str, List[str]],
    ) -> None:
        for m in _GO_IMPORT_TARGET_RE.finditer(stmt):
            alias = m.group(1)
            path = m.group(2)
            if not path or "/" not in path and "." not in path:
                continue
            bound = alias or path.rsplit("/", 1)[-1]
            out.setdefault(bound, []).append(path)

    def tree_sitter_language(self) -> Optional["Language"]:
        from tree_sitter import Language

        from ..native_analyzer import _get_language_module

        lang_mod = _get_language_module(self.LANGUAGE)
        if lang_mod is None:
            return None
        return Language(lang_mod.language())


ADAPTER = GoAdapter()

__all__ = ["GoAdapter", "ADAPTER"]
