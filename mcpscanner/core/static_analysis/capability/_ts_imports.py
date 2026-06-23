# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared TypeScript / JavaScript import-statement parser.

JS and TS share an import grammar (TS adds type-only imports but
they're a strict superset for the bound-name extraction we care
about). Rather than make either language adapter subclass the other —
the issue's design notes explicitly call out that subclassing JS from
TS would couple grammar quirks across the two languages —
:py:func:`collect_import_targets` lives here as a free function that
both adapters delegate to.
"""

from __future__ import annotations

import re
from typing import Dict, List


def collect_import_targets(stmt: str, out: Dict[str, List[str]]) -> None:
    """Populate ``out`` from one TS / JS import statement.

    Handles:

    * ``import default from "..."``
    * ``import { a, b as c } from "..."``
    * ``import * as ns from "..."``
    * ``import default, { ... } from "..."``
    * ``const x = require("...")``

    Each bound name is mapped to its module path-suffix candidate (no
    extension, forward slashes); see
    :py:func:`._normalize_module_specifier` for the canonical form.
    The function tolerates malformed lines silently — the cross-file
    resolver falls back to the bare-suffix matcher when nothing
    matches.
    """
    # Lazy import to avoid the upward dependency on capability_detector
    # at module-import time. capability_detector imports the registry,
    # so eager import here would create a cycle.
    from ..capability_detector import _normalize_module_specifier

    # ``import <clause> from "<module>"``
    m = re.match(
        r"""^import\s+(.*?)\s+from\s+['"]([^'"]+)['"]""",
        stmt,
    )
    if m:
        clause = m.group(1).strip()
        path = _normalize_module_specifier(m.group(2))
        if not path:
            return
        # ``import * as ns from "..."``
        ns = re.match(r"^\*\s+as\s+(\w+)$", clause)
        if ns:
            out.setdefault(ns.group(1), []).append(path)
            return
        # ``import default, { a, b as c } from "..."`` — split
        # default-import + named-import block.
        if not clause.startswith("{"):
            head, _, rest = clause.partition(",")
            head = head.strip()
            if head:
                out.setdefault(head, []).append(path)
            clause = rest.strip()
        m2 = re.match(r"^\{(.*)\}$", clause, re.DOTALL)
        if m2:
            for piece in m2.group(1).split(","):
                piece = piece.strip()
                if not piece:
                    continue
                parts = re.split(r"\s+as\s+", piece, maxsplit=1)
                bound = (
                    parts[1].strip()
                    if len(parts) > 1
                    else parts[0].strip()
                )
                if bound:
                    out.setdefault(bound, []).append(path)
        return
    # ``const x = require("./tools/add")`` — best-effort.
    m = re.match(
        r"""^(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
        stmt,
    )
    if m:
        bound = m.group(1)
        path = _normalize_module_specifier(m.group(2))
        if path:
            out.setdefault(bound, []).append(path)


__all__ = ["collect_import_targets"]
