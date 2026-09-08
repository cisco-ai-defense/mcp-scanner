# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for behavioral test modules."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

import pytest


def _snapshot_logger(logger: logging.Logger) -> dict:
    return {
        "logger": logger,
        "level": logger.level,
        "propagate": logger.propagate,
        "handler_levels": [(handler, handler.level) for handler in logger.handlers],
    }


def _restore_logger(snapshot: dict) -> None:
    logger = snapshot["logger"]
    logger.setLevel(snapshot["level"])
    logger.propagate = snapshot["propagate"]
    for handler, level in snapshot["handler_levels"]:
        handler.setLevel(level)


def _mcpscanner_logger_snapshots() -> list[dict]:
    snapshots: list[dict] = []
    seen: set[str] = set()
    for name in list(logging.Logger.manager.loggerDict.keys()):
        if not name.startswith("mcpscanner"):
            continue
        if name in seen:
            continue
        seen.add(name)
        candidate = logging.Logger.manager.loggerDict[name]
        if isinstance(candidate, logging.Logger):
            snapshots.append(_snapshot_logger(candidate))
    root = logging.getLogger("mcpscanner")
    if root.name not in seen:
        snapshots.append(_snapshot_logger(root))
    return snapshots


@contextmanager
def restore_mcpscanner_logging() -> Iterator[None]:
    """Snapshot and restore mcpscanner logger levels, handlers, and propagate."""
    snapshots = _mcpscanner_logger_snapshots()
    try:
        yield
    finally:
        for snapshot in snapshots:
            _restore_logger(snapshot)


@pytest.fixture
def mcpscanner_logging_isolated():
    """Prevent behavioral tests from leaking global mcpscanner logging state."""
    with restore_mcpscanner_logging():
        yield
