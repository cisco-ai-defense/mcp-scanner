# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Lazy loader for compiled capability ``.scm`` queries.

The loader keeps tree-sitter ``Query`` objects per ``(language, name)``
so that:

* The ``.scm`` source on disk is read at most once per process.
* Compiled queries are reused across files of the same language —
  compiling a query is the bulk of the cost; running it against a
  parsed tree is cheap.
* Languages that have no queries yet (e.g. ``kotlin``, ``rust``) fall
  back to the imperative walks transparently — callers ask
  :py:meth:`CapabilityQueryLoader.bundle` for a language and get
  ``None`` if no queries are registered.

Receiver-type verification and SDK-import bookkeeping stay in Python.
The loader only deals with *pattern matching* — semantic validation is
the caller's job, exactly the division of labour described in the
follow-up issue.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, Iterable, Optional, Tuple

if TYPE_CHECKING:
    from tree_sitter import Language, Node, Query

logger = logging.getLogger(__name__)

# Query file names. Each language directory contains a subset of these
# files; missing queries cause the imperative fallback to run for that
# pattern, which keeps the loader composable while we migrate.
QUERY_NAMES: Tuple[str, ...] = (
    "registrations",
    "low_level",
    "functions",
    "instantiations",
    "annotations",
)

# Languages that ship at least one ``.scm`` file under
# ``capability_queries/<lang>/``. Sources of truth: the directory
# contents on disk, surfaced here for fast existence checks.
SUPPORTED_LANGUAGES: Tuple[str, ...] = (
    "typescript",
    "javascript",
    "go",
)


@dataclass(slots=True)
class QueryBundle:
    """All queries available for a language.

    Each attribute is an ``Optional[Query]``. ``None`` means "no
    ``.scm`` file shipped for this pattern in this language yet" — the
    caller falls back to the imperative walker. As more languages get
    ``.scm`` files, more attributes flip from ``None`` to a compiled
    query without changing call-site code.
    """

    language: str
    registrations: Optional["Query"] = None
    low_level: Optional["Query"] = None
    functions: Optional["Query"] = None
    instantiations: Optional["Query"] = None
    annotations: Optional["Query"] = None

    def get(self, name: str) -> Optional["Query"]:
        """Return the compiled query for ``name`` or ``None`` if missing."""
        return getattr(self, name, None)


# Maps the value passed to :py:meth:`CapabilityQueryLoader.bundle` to
# the directory under ``capability_queries/`` whose ``.scm`` files we
# load. Two languages can point at the same directory when their
# tree-sitter grammars produce equivalent shapes for the patterns we
# care about (JS and TS share ``call_expression`` /
# ``member_expression`` / ``arrow_function`` etc.).
_LANGUAGE_QUERY_DIR: Dict[str, str] = {
    "typescript": "typescript",
    "tsx": "typescript",
    "javascript": "javascript",
    "go": "go",
}


# ----------------------------------------------------------------------
# Tree-sitter ``Language`` objects are produced by the per-language
# packages; importing them lazily keeps the rest of the codebase
# unchanged when a particular language isn't installed.
# ----------------------------------------------------------------------


def _ts_language_factory(name: str) -> "Language":
    """Return the ``tree_sitter.Language`` for ``name``.

    Mirrors :func:`mcpscanner.core.static_analysis.native_analyzer._get_language_module`
    but lives here so the loader stays self-contained — the loader can
    be instantiated without importing the full native_analyzer module.
    Imports are lazy on purpose so that adding a new query-supported
    language doesn't add hard dependencies for users who don't scan
    that language.
    """
    from tree_sitter import Language  # local import: tree_sitter is a runtime dep

    if name in ("typescript", "tsx"):
        import tree_sitter_typescript

        if name == "tsx":
            return Language(tree_sitter_typescript.language_tsx())
        return Language(tree_sitter_typescript.language_typescript())
    if name == "javascript":
        import tree_sitter_javascript

        return Language(tree_sitter_javascript.language())
    if name == "go":
        import tree_sitter_go

        return Language(tree_sitter_go.language())
    raise KeyError(f"No tree-sitter Language factory wired for: {name}")


class CapabilityQueryLoader:
    """Process-wide loader for capability ``.scm`` queries.

    Use the singleton :py:func:`get_loader` for normal callers; the
    class is exported for unit tests that want isolated loaders.
    """

    def __init__(
        self,
        root_dir: Optional[Path] = None,
        *,
        language_factory: Callable[[str], "Language"] = _ts_language_factory,
    ) -> None:
        # Default root: the ``capability_queries/`` directory next to
        # this file. Tests can pass a different root to exercise broken
        # / synthetic ``.scm`` files in isolation.
        self._root = root_dir or Path(__file__).resolve().parent
        self._language_factory = language_factory
        self._bundles: Dict[str, QueryBundle] = {}
        # Compiled-query cache is implicit via ``_bundles`` (one bundle
        # per language). ``_lock`` only guards bundle initialization;
        # query objects are immutable once compiled.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def bundle(self, language: str) -> Optional[QueryBundle]:
        """Return the compiled :class:`QueryBundle` for ``language``.

        ``None`` when no ``.scm`` files are shipped for that language
        — callers should fall back to the imperative walker. Idempotent
        and thread-safe.
        """
        sub = _LANGUAGE_QUERY_DIR.get(language)
        if sub is None:
            return None

        cached = self._bundles.get(sub)
        if cached is not None:
            return cached

        with self._lock:
            cached = self._bundles.get(sub)
            if cached is not None:
                return cached

            bundle = self._load_bundle(sub)
            # Empty bundles (no ``.scm`` files at all) still get
            # cached so we don't re-stat the directory on every call.
            self._bundles[sub] = bundle
            return bundle

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _load_bundle(self, sub: str) -> Optional[QueryBundle]:
        from tree_sitter import Query  # local import: keeps optional deps lazy

        directory = self._root / sub
        if not directory.is_dir():
            return None

        try:
            ts_language = self._language_factory(sub)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(
                "capability_queries: could not load tree-sitter language for %s: %s",
                sub,
                exc,
            )
            return None

        bundle = QueryBundle(language=sub)
        compiled_any = False
        for name in QUERY_NAMES:
            scm_path = directory / f"{name}.scm"
            if not scm_path.is_file():
                continue
            try:
                source = scm_path.read_text(encoding="utf-8")
            except OSError as exc:
                logger.debug(
                    "capability_queries: could not read %s: %s", scm_path, exc
                )
                continue
            try:
                query = Query(ts_language, source)
            except Exception as exc:
                # Bad ``.scm`` should never silently produce wrong
                # results — surface the failure at debug level and skip
                # the query so the imperative walker still runs.
                logger.warning(
                    "capability_queries: failed to compile %s: %s", scm_path, exc
                )
                continue
            setattr(bundle, name, query)
            compiled_any = True

        if not compiled_any:
            return None
        return bundle


# ----------------------------------------------------------------------
# Module-level singleton. The loader is process-wide because compiled
# queries are immutable and re-compiling them per scan is wasteful.
# ----------------------------------------------------------------------

_DEFAULT_LOADER: Optional[CapabilityQueryLoader] = None
_DEFAULT_LOADER_LOCK = threading.Lock()


def get_loader() -> CapabilityQueryLoader:
    """Return the process-wide :class:`CapabilityQueryLoader` singleton."""
    global _DEFAULT_LOADER
    if _DEFAULT_LOADER is None:
        with _DEFAULT_LOADER_LOCK:
            if _DEFAULT_LOADER is None:
                _DEFAULT_LOADER = CapabilityQueryLoader()
    return _DEFAULT_LOADER


def get_bundle(language: str) -> Optional[QueryBundle]:
    """Convenience wrapper around :py:meth:`CapabilityQueryLoader.bundle`."""
    return get_loader().bundle(language)
