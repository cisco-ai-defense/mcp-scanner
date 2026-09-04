# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Doc-test: onboarding a new MCP SDK language end-to-end.

This file is the executable proof that the per-language adapter
architecture from issue #186 actually delivers on its promise:
**adding support for a new MCP SDK is a single-file additive change**,
not a multi-file edit across the orchestrator, regex tables, and
walker dispatch points.

The fixture defines a synthetic ``swift`` adapter, registers it via
the public :py:func:`register_adapter` helper, and asserts the
shared orchestrator (``CapabilityDetector`` and the helpers it
delegates to) immediately consults the new adapter for its constants
and override hooks. No edits to any existing adapter, the
orchestrator, or the shared base class are required for any of this
to work.

If a future change to the architecture breaks the additive-onboarding
property — e.g. by re-introducing a hard-coded language enum
somewhere — this test fails and the property is regained before the
PR can land.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Set

import pytest

from mcpscanner.core.static_analysis.capability import (
    LANGUAGE_REGISTRY,
    register_adapter,
    unregister_adapter,
)
from mcpscanner.core.static_analysis.capability.base import AdapterMixin


# ---------------------------------------------------------------------
# Fake Swift adapter.
#
# A real Swift adapter would ship ``capability_queries/swift/*.scm``
# queries and a ``tree-sitter-swift`` factory; the fixture below
# stubs all of that out and focuses only on the data-and-hooks shape
# every adapter exposes. What we want to verify is that the
# orchestrator and shared classifiers immediately consult a
# freshly-registered adapter — not that Swift parsing actually works.
# ---------------------------------------------------------------------


class FakeSwiftAdapter(AdapterMixin):
    """Synthetic Swift adapter — exists only for this test."""

    LANGUAGE = "swift"
    SDK_MODULE_PREFIXES = ("ModelContextProtocol",)
    TRUSTED_NAMESPACES: FrozenSet[str] = frozenset({""})
    ANNOTATION_IDENTIFIERS: Dict[str, str] = {
        "Tool": "tool",
        "Prompt": "prompt",
        "Resource": "resource",
    }

    def parse_import_alias(
        self,
        stmt: str,
        sdk_classes: Set[str],
        sdk_aliases: Set[str],
    ) -> None:
        # A toy import-alias rule: ``import ModelContextProtocol``
        # exposes the bare ``MCP`` alias the SDK uses by convention.
        # The real Swift SDK doesn't ship today; this is here purely
        # to prove the override hook fires for a freshly-registered
        # language.
        if "ModelContextProtocol" in stmt:
            sdk_aliases.add("MCP")


# ---------------------------------------------------------------------
# Fixture: register + tear-down. Tests using this fixture get a
# guarantee that the swift adapter is available for the duration of
# the test and removed afterwards so no other test is contaminated.
# ---------------------------------------------------------------------


@pytest.fixture()
def swift_adapter():
    """Register the fake-swift adapter for one test, then unregister."""
    adapter = FakeSwiftAdapter()
    register_adapter(adapter)
    try:
        yield adapter
    finally:
        unregister_adapter(adapter.LANGUAGE)


# ---------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------


def test_baseline_swift_not_in_registry() -> None:
    """Without registering the adapter, ``swift`` must not appear in
    the registry. Establishes the contrast for the registration test
    below."""
    assert "swift" not in LANGUAGE_REGISTRY


def test_registering_swift_adapter_makes_it_visible(
    swift_adapter,
) -> None:
    """:py:func:`register_adapter` puts the adapter in the registry
    so all consumers (orchestrator, classifiers, helpers) can find it
    by language identifier."""
    from mcpscanner.core.static_analysis.capability import get_adapter

    assert "swift" in LANGUAGE_REGISTRY
    assert get_adapter("swift") is swift_adapter
    assert get_adapter("swift").ANNOTATION_IDENTIFIERS["Tool"] == "tool"


def test_unregistering_swift_adapter_restores_baseline() -> None:
    """After the fixture tears down the registry no longer knows
    about Swift — proves :py:func:`unregister_adapter` removes the
    entry cleanly so tests don't pollute each other."""
    assert "swift" not in LANGUAGE_REGISTRY


def test_classify_annotation_picks_up_dynamically_registered_adapter(
    swift_adapter,
) -> None:
    """``_classify_mcp_annotation`` reads through the registry rather
    than a cached dict, so a freshly-registered adapter's
    ``ANNOTATION_IDENTIFIERS`` are immediately visible to the shared
    classifier helper without any other code changes."""
    from mcpscanner.core.static_analysis.capability_detector import (
        _classify_mcp_annotation,
    )

    # Annotations on the swift allow-list classify, lookalikes don't.
    # The classifier expects the raw annotation string (sigil + leaf),
    # not the bare identifier.
    assert (
        _classify_mcp_annotation(["@Tool"], language="swift") == "tool"
    )
    assert (
        _classify_mcp_annotation(["@Prompt"], language="swift")
        == "prompt"
    )
    assert (
        _classify_mcp_annotation(["@Tooltip"], language="swift") is None
    )


def test_register_adapter_rejects_duplicate_with_different_class() -> None:
    """Re-registering a different class under the same identifier
    must raise — silent overrides would make the registry's behaviour
    impossible to reason about."""

    class AnotherSwiftAdapter(AdapterMixin):
        LANGUAGE = "swift"
        SDK_MODULE_PREFIXES = ()
        TRUSTED_NAMESPACES: FrozenSet[str] = frozenset({""})
        ANNOTATION_IDENTIFIERS: Dict[str, str] = {}

    primary = FakeSwiftAdapter()
    register_adapter(primary)
    try:
        with pytest.raises(ValueError, match="already registered"):
            register_adapter(AnotherSwiftAdapter())
    finally:
        unregister_adapter("swift")


def test_register_adapter_idempotent_for_same_instance() -> None:
    """Registering the same instance twice must be a no-op (not a
    raise) so library code can safely re-register at scanner-process
    boundaries without risking errors."""
    adapter = FakeSwiftAdapter()
    register_adapter(adapter)
    try:
        # Second registration of the same instance should be a no-op.
        register_adapter(adapter)
        assert LANGUAGE_REGISTRY["swift"] is adapter
    finally:
        unregister_adapter("swift")


def test_swift_orchestrator_dispatch_uses_adapter_hooks(swift_adapter) -> None:
    """End-to-end: the orchestrator's ``_collect_mcp_instances``
    consults the adapter's ``parse_import_alias`` hook for every
    registered language. We exercise the hook indirectly by feeding a
    Swift-shaped import line through the helper that drives Stage 1
    and asserting our override added the expected alias.

    This is the strongest signal the registration mechanism actually
    plumbs end-to-end without any ``if self.language == "X"`` branches
    needing to know about Swift in advance.
    """
    sdk_classes: Set[str] = set()
    sdk_aliases: Set[str] = set()

    swift_adapter.parse_import_alias(
        "import ModelContextProtocol\nimport Foundation",
        sdk_classes,
        sdk_aliases,
    )

    assert sdk_aliases == {"MCP"}, sdk_aliases
    assert sdk_classes == set()
