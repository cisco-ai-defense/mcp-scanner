# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Process-wide registry of language adapters.

The registry is the single source of truth for "which languages have
an MCP capability adapter" and is used by the orchestrator to dispatch
language-specific behaviour without ``if self.language == "X"``
branches.

Adapters are registered eagerly the first time the registry is queried
(see :py:func:`_ensure_default_adapters_registered`); this avoids
pulling in every tree-sitter grammar when callers only care about one
language but still surfaces typos / import errors at startup rather
than scan time.

Tests that need to swap an adapter — for example, the fake-swift
onboarding fixture that proves the registration mechanism works
end-to-end — should use :py:func:`register_adapter` /
:py:func:`unregister_adapter` directly.
"""

from __future__ import annotations

import threading
from typing import Dict, Optional, Tuple

from .base import LanguageAdapter

# Module-level singleton. Populated by ``_ensure_default_adapters_registered``
# on first read. Tests may register / unregister synthetic adapters
# at any time via the public helpers below.
LANGUAGE_REGISTRY: Dict[str, LanguageAdapter] = {}
_REGISTRY_LOCK = threading.Lock()
_DEFAULTS_REGISTERED = False


def register_adapter(adapter: LanguageAdapter) -> None:
    """Register ``adapter`` under its ``LANGUAGE`` identifier.

    Idempotent: registering the same instance twice is a no-op.
    Registering a *different* adapter under an identifier that's
    already taken raises ``ValueError`` to prevent silent overrides
    during normal startup. Tests that need to swap an adapter should
    call :py:func:`unregister_adapter` first.
    """
    if not hasattr(adapter, "LANGUAGE"):
        raise TypeError(
            f"adapter {adapter!r} does not declare a LANGUAGE class attribute"
        )
    language = adapter.LANGUAGE
    with _REGISTRY_LOCK:
        existing = LANGUAGE_REGISTRY.get(language)
        if existing is None:
            LANGUAGE_REGISTRY[language] = adapter
            return
        if existing is adapter:
            return
        raise ValueError(
            f"language adapter for {language!r} already registered "
            f"({type(existing).__name__}); refusing to override with "
            f"{type(adapter).__name__}"
        )


def unregister_adapter(language: str) -> Optional[LanguageAdapter]:
    """Remove and return the adapter registered for ``language``.

    Returns ``None`` if no adapter was registered.
    """
    with _REGISTRY_LOCK:
        return LANGUAGE_REGISTRY.pop(language, None)


def get_adapter(language: str) -> Optional[LanguageAdapter]:
    """Return the registered adapter for ``language``, or ``None``.

    Triggers lazy registration of the bundled adapters on first call;
    subsequent calls are O(1) dict lookups.
    """
    _ensure_default_adapters_registered()
    return LANGUAGE_REGISTRY.get(language)


def supported_languages() -> Tuple[str, ...]:
    """Return the tuple of registered language identifiers, sorted.

    Stable across calls within one process so callers can use it to
    drive parametrized tests or capability menus.
    """
    _ensure_default_adapters_registered()
    return tuple(sorted(LANGUAGE_REGISTRY.keys()))


def _ensure_default_adapters_registered() -> None:
    """Eagerly import and register the bundled language adapters.

    Idempotent and thread-safe. Each adapter module exports an
    ``ADAPTER`` singleton; we import the modules in a stable order
    purely for predictable registration logs — the registry itself is
    keyed by ``LANGUAGE``.
    """
    global _DEFAULTS_REGISTERED
    if _DEFAULTS_REGISTERED:
        return
    with _REGISTRY_LOCK:
        if _DEFAULTS_REGISTERED:
            return

        # Import side effects: each module defines a module-level
        # ``ADAPTER`` instance we register below. Import order is
        # purely cosmetic; the registry is keyed by ``LANGUAGE``.
        from . import (  # noqa: F401
            csharp as _cs,
            go as _go,
            java as _java,
            javascript as _js,
            kotlin as _kt,
            php as _php,
            python as _py,
            ruby as _rb,
            rust as _rs,
            typescript as _ts,
        )

        modules = (_py, _js, _ts, _go, _kt, _java, _cs, _rs, _php, _rb)
        for module in modules:
            adapter = getattr(module, "ADAPTER", None)
            if adapter is None:
                # A module without an ``ADAPTER`` is a bug — every
                # bundled language adapter is expected to expose one.
                raise RuntimeError(
                    f"capability adapter module {module.__name__} did not "
                    f"expose an ADAPTER attribute"
                )
            # Direct mutation here (instead of register_adapter) because
            # the lock is already held.
            existing = LANGUAGE_REGISTRY.get(adapter.LANGUAGE)
            if existing is None:
                LANGUAGE_REGISTRY[adapter.LANGUAGE] = adapter
            elif existing is not adapter:
                raise ValueError(
                    f"duplicate adapter for {adapter.LANGUAGE!r}: "
                    f"{type(existing).__name__} vs {type(adapter).__name__}"
                )

        _DEFAULTS_REGISTERED = True


__all__ = [
    "LANGUAGE_REGISTRY",
    "register_adapter",
    "unregister_adapter",
    "get_adapter",
    "supported_languages",
]
