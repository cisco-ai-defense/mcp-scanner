# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language MCP capability detection.

This package replaces the in-line ``if self.language == "X"`` branching
that used to live in ``capability_detector.py`` with a per-language
adapter pattern. Each supported language ships a tiny module under
``capability/`` that owns:

* its SDK module specifier list (``sdk_module_prefixes``);
* its trusted-namespace allow-list (``trusted_namespaces``);
* its annotation/attribute identifier mapping
  (``annotation_identifiers``);
* method overrides for the small handful of operations that genuinely
  need per-language behavior (Stage-1 import-alias parsing, the
  cross-file import-target map, the tree-sitter ``Language`` factory).

Behaviour is preserved exactly — adapters are pure refactors of the
data and conditional dispatch that already existed. The big shared
helpers (registration walker, instance collector, annotation walker,
…) stay generic on :class:`CapabilityDetector` because they were
already factored to handle every grammar shape via node-type checks
rather than language equality, and the migration to ``.scm`` queries
in ``capability_queries/`` further reduces the language-specific
imperative code paths.

Adding a new language now means:

1. Creating ``capability/<lang>.py`` with the four/five constants and
   the :class:`LanguageAdapter` Protocol implementation.
2. Registering it in :data:`LANGUAGE_REGISTRY` (one line).
3. Optionally shipping ``.scm`` queries under
   ``capability_queries/<lang>/``.

No edits to existing language files — that's the discoverability win
the surrounding issue called out.
"""

from __future__ import annotations

from .base import (
    CapabilityRecord,
    LanguageAdapter,
)
from .registry import (
    LANGUAGE_REGISTRY,
    get_adapter,
    register_adapter,
    supported_languages,
    unregister_adapter,
)

__all__ = [
    "CapabilityRecord",
    "LanguageAdapter",
    "LANGUAGE_REGISTRY",
    "get_adapter",
    "register_adapter",
    "supported_languages",
    "unregister_adapter",
]
