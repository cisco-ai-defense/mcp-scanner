# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared base types for per-language capability detection adapters.

Defines the contract every language adapter implements so the
orchestrator (:class:`mcpscanner.core.static_analysis.capability_detector.CapabilityDetector`)
can dispatch on it without knowing language identifiers.

This module does NOT carry a tree-sitter or ``ast`` dependency — those
are pulled in lazily by individual adapters so importing this file is
cheap regardless of which grammars happen to be installed in the host
environment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Protocol,
    Set,
    Tuple,
    runtime_checkable,
)

if TYPE_CHECKING:
    from tree_sitter import Language


@dataclass
class CapabilityRecord:
    """Lightweight value object describing one detected MCP capability.

    The orchestrator returns rich :class:`FunctionContext` objects to
    callers (because that's what the existing public API contracts
    expose), but adapter-level helpers operate on this thinner shape.
    Translating ``CapabilityRecord`` -> ``FunctionContext`` happens in
    one place in :class:`CapabilityDetector` so adapters stay free of
    presentation concerns.

    ``decorator_types`` lists the markers that classified this record
    (``@tool``, ``[McpServerTool]``, ``#[tool]`` …); downstream code
    uses it for source-attribution and dedup keys.
    """

    name: Optional[str] = None
    capability: Optional[str] = None  # "tool" | "prompt" | "resource"
    handler_node: Any = None
    handler_name: Optional[str] = None
    template_subtype: Optional[str] = None
    decorator_types: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)


# ----------------------------------------------------------------------
# Adapter contract.
#
# Every concrete adapter is a small, mostly-data class that implements
# the :class:`LanguageAdapter` Protocol. Methods that are genuinely
# language-specific (import-alias parsing, the tree-sitter Language
# factory) are interface methods with sensible no-op defaults provided
# by :class:`AdapterMixin`. Concrete adapters typically only override
# the methods that actually differ from the no-op default.
#
# We use a Protocol (vs an ABC) because:
#
# * Adapters are pure-data + a few small methods; no shared state.
# * ``runtime_checkable`` lets the registry validate concrete classes
#   at registration time without forcing every adapter to inherit a
#   common base — composition over inheritance is the explicit goal.
# * Test-only adapters (e.g. the fake-swift onboarding test) can be
#   any class that supplies the right attributes; they don't need to
#   import or subclass anything from this module.
# ----------------------------------------------------------------------


@runtime_checkable
class LanguageAdapter(Protocol):
    """Per-language MCP detection adapter.

    Static class attributes (data):

    * :attr:`LANGUAGE` — canonical language identifier (matches the
      ``self.language`` value the analyzer produces from file
      extensions).
    * :attr:`SDK_MODULE_PREFIXES` — lower-case substrings of import
      module specifiers that signal the import comes from a recognized
      MCP SDK.
    * :attr:`TRUSTED_NAMESPACES` — namespace prefixes that, when seen
      in front of generic identifiers (``Tool``/``Prompt``/``Resource``),
      let the bare leaf name classify as MCP. Empty string means "no
      namespace" — bare identifiers at the import root.
    * :attr:`ANNOTATION_IDENTIFIERS` — mapping from a (possibly
      lower-cased) annotation/attribute/macro identifier to its MCP
      capability kind (``"tool"``/``"prompt"``/``"resource"``).

    Methods:

    * :py:meth:`parse_import_alias` — Stage-1 hook for the instance
      collector. Languages whose import grammar exposes an SDK alias
      (``import alias "github.com/.../mcp"`` for Go) override this to
      add the alias to ``sdk_aliases``. Default no-op.
    * :py:meth:`parse_import_target` — Cross-file resolver hook. Adds
      ``{bound_name: [path-suffix]}`` entries for one import line.
      Default no-op.
    * :py:meth:`tree_sitter_language` — Returns the
      :class:`tree_sitter.Language` for this adapter's grammar. Returns
      ``None`` for languages whose detector doesn't use tree-sitter
      (Python uses the ``ast`` module).
    """

    LANGUAGE: str
    SDK_MODULE_PREFIXES: Tuple[str, ...]
    TRUSTED_NAMESPACES: FrozenSet[str]
    ANNOTATION_IDENTIFIERS: Dict[str, str]

    def parse_import_alias(
        self,
        stmt: str,
        sdk_classes: Set[str],
        sdk_aliases: Set[str],
    ) -> None:
        ...

    def parse_import_target(
        self,
        stmt: str,
        out: Dict[str, List[str]],
    ) -> None:
        ...

    def tree_sitter_language(self) -> Optional["Language"]:
        ...

    def extract_with_native_parser(
        self,
        detector: Any,
        cross_file_analyzer: Optional[Any] = None,
    ) -> Optional[List[Any]]:
        ...


# ----------------------------------------------------------------------
# Concrete-class helper.
#
# Most adapters look like::
#
#   class JavaAdapter(AdapterMixin):
#       LANGUAGE = "java"
#       SDK_MODULE_PREFIXES = (...)
#       TRUSTED_NAMESPACES = frozenset({"", ...})
#       ANNOTATION_IDENTIFIERS = {...}
#
#       def tree_sitter_language(self):
#           import tree_sitter_java
#           return Language(tree_sitter_java.language())
#
# Inheriting from :class:`AdapterMixin` gives them no-op defaults for
# the optional methods so they only need to implement the methods that
# matter for them.
# ----------------------------------------------------------------------


class AdapterMixin:
    """No-op default implementations for the optional adapter methods.

    Concrete adapters can drop this in to skip implementing methods
    they don't need. The mixin deliberately doesn't define any of the
    ``LANGUAGE`` / ``SDK_MODULE_PREFIXES`` / ... class attributes —
    those MUST be supplied by the concrete adapter so a missing
    attribute is a hard error at class definition time, not a
    silently-empty default at runtime.
    """

    def parse_import_alias(
        self,
        stmt: str,
        sdk_classes: Set[str],
        sdk_aliases: Set[str],
    ) -> None:
        """Default no-op. Override for languages whose import grammar
        introduces an SDK *alias* (Go's ``import alias "..."``,
        Kotlin's ``import io.modelcontextprotocol.X`` rebinding, ...)."""

    def parse_import_target(
        self,
        stmt: str,
        out: Dict[str, List[str]],
    ) -> None:
        """Default no-op. Override to populate ``{bound_name: [paths]}``
        from one import statement. Used by the cross-file handler
        resolver; languages without a target map fall back to the
        bare-suffix matcher."""

    def tree_sitter_language(self) -> Optional["Language"]:
        """Default returns ``None`` (no tree-sitter grammar — Python
        uses the ``ast`` module). Tree-sitter languages override and
        return the compiled :class:`tree_sitter.Language`."""
        return None

    def extract_with_native_parser(
        self,
        detector: Any,
        cross_file_analyzer: Optional[Any] = None,
    ) -> Optional[List[Any]]:
        """Adapter-specific entry point for languages that don't use
        the shared tree-sitter walker.

        Returning a list (possibly empty) tells the orchestrator
        "I handled detection, use this result as-is". Returning ``None``
        tells the orchestrator to fall through to the generic
        tree-sitter walker (the common case — only Python overrides).
        """
        return None


__all__ = [
    "CapabilityRecord",
    "LanguageAdapter",
    "AdapterMixin",
]
