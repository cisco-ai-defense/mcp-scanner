# Copyright 2025 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Tests for :class:`CapabilityQueryLoader`.

The loader is the only place where ``.scm`` files are read from disk
and compiled, so it carries the single-source-of-truth invariants for
the migration. We validate:

* The shipped languages all produce a non-``None`` :class:`QueryBundle`.
* Languages without ``.scm`` files (Python, Kotlin, etc.) return
  ``None`` so the dispatcher falls back to the imperative walker.
* Each bundle exposes the expected query attributes.
* Bundles are cached — repeated calls return the same object.
"""

from __future__ import annotations

import pytest

from mcpscanner.core.static_analysis.capability_queries import (
    QUERY_NAMES,
    SUPPORTED_LANGUAGES,
    CapabilityQueryLoader,
    get_loader,
)


def test_query_names_are_the_canonical_set():
    assert set(QUERY_NAMES) == {
        "registrations",
        "low_level",
        "functions",
        "instantiations",
        "annotations",
    }


def test_supported_languages_match_shipped_directories():
    """All ``SUPPORTED_LANGUAGES`` produce a real bundle.

    The list is the source of truth surfaced to the rest of the
    codebase; the loader's directory probe and the constant must
    agree.
    """
    loader = get_loader()
    for lang in SUPPORTED_LANGUAGES:
        bundle = loader.bundle(lang)
        assert bundle is not None, f"no bundle for {lang}"
        assert bundle.language == lang


def test_unsupported_language_returns_none():
    """Languages without query files (Python, Kotlin, …) fall through
    to the imperative walker — represented as ``None`` here."""
    loader = get_loader()
    assert loader.bundle("python") is None
    assert loader.bundle("kotlin") is None
    assert loader.bundle("") is None


def test_bundle_is_cached():
    """The loader compiles each query at most once."""
    loader = CapabilityQueryLoader()
    first = loader.bundle("typescript")
    second = loader.bundle("typescript")
    assert first is second


@pytest.mark.parametrize(
    "language,expected_present",
    [
        ("typescript", {"registrations", "low_level", "functions", "instantiations"}),
        ("javascript", {"registrations", "low_level", "functions", "instantiations"}),
        ("go", {"registrations", "functions", "instantiations"}),
    ],
)
def test_bundle_exposes_expected_queries(language, expected_present):
    """Each shipped language has at least these queries compiled.

    Annotations are optional everywhere right now; we only assert the
    minimal set called out in the issue's acceptance criteria.
    """
    bundle = get_loader().bundle(language)
    assert bundle is not None
    for name in expected_present:
        assert bundle.get(name) is not None, (
            f"{language}/{name}.scm missing or did not compile"
        )


def test_tsx_aliases_to_typescript_directory():
    """``.tsx`` resolves to the TypeScript bundle so JSX-flavoured TS
    files don't fall back to the imperative walker by accident."""
    loader = CapabilityQueryLoader()
    ts = loader.bundle("typescript")
    tsx = loader.bundle("tsx")
    assert ts is not None and tsx is not None
    # Same compiled queries — the loader maps both to the same dir.
    assert ts is tsx
