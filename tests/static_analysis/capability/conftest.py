# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the per-language capability test modules.

Each :file:`test_<lang>.py` exercises a single language end-to-end —
helpers-only files yield ``[]``, mixed files yield only the
registered/annotated capability, and the synthetic source-kind tag
matches the SDK's discovery shape (``<annotation>.tool`` for
attribute/macro-driven SDKs, ``<registration>.tool`` for call-site
registration SDKs). Tests are scoped to one language so a grammar
regression in (say) Kotlin can't take Go's tests down with it; this is
the test-isolation property the surrounding refactor was after.
"""

from __future__ import annotations

from typing import Iterable, Set

from mcpscanner.core.static_analysis import NativeAnalyzer
from mcpscanner.core.static_analysis.context_extractor import FunctionContext


def names_of(caps: Iterable[FunctionContext]) -> Set[str]:
    """Return the bag of ``FunctionContext.name`` values."""
    return {c.name for c in caps}


def assert_helpers_only(source: str, path: str) -> None:
    """Assert a helpers-only file yields zero capabilities."""
    analyzer = NativeAnalyzer(source, path)
    caps = analyzer.extract_mcp_capability_contexts()
    assert caps == [], (
        f"helpers-only fixture for {path!r} unexpectedly returned "
        f"{names_of(caps)!r}"
    )


def assert_mixed_yields(
    source: str, path: str, expected_names: Set[str]
) -> None:
    """Assert a mixed file (1 MCP cap + N helpers) returns exactly
    ``expected_names`` and that helpers are filtered out."""
    analyzer = NativeAnalyzer(source, path)
    caps = analyzer.extract_mcp_capability_contexts()
    assert names_of(caps) == expected_names, (
        f"{path!r}: got {names_of(caps)!r} but expected "
        f"{expected_names!r}"
    )
    full = analyzer.analyze()
    assert full.success
    assert len(full.functions) > len(caps), (
        f"{path!r}: extract_mcp_capability_contexts() returned the same "
        f"number of contexts as extract_all_function_contexts(); the test "
        f"fixture must contain at least one non-capability helper."
    )


def assert_source_kind_tag(
    source: str, path: str, expected_tag: str
) -> None:
    """Assert the synthetic source-kind tag matches the discovery
    shape for the SDK (``<annotation>.tool`` vs ``<registration>.tool``).
    """
    analyzer = NativeAnalyzer(source, path)
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, names_of(caps)
    assert expected_tag in caps[0].decorator_types, caps[0].decorator_types
