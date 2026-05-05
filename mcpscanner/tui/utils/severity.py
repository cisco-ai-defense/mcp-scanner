# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Shared severity helpers for the Textual UI.

Single source of truth for:
- Severity rollup (delegates to :func:`mcpscanner.core.result.get_highest_severity`).
- The hex color palette used for severity badges, tables, and the stats bar.
- Rich markup for styled severity text.

Other ``mcpscanner.tui.*`` modules MUST import these helpers instead of
re-defining their own copies.
"""

from __future__ import annotations

from typing import Iterable

from mcpscanner.core.result import get_highest_severity

#: Mapping from canonical severity label -> hex color used in the TUI.
#:
#: The palette mirrors the GitHub semantic-color set:
#: - ``HIGH``    red
#: - ``MEDIUM``  amber
#: - ``LOW``     yellow
#: - ``INFO``    teal
#: - ``SAFE``    green
#: - ``UNKNOWN`` purple (distinct from HIGH so that "didn't run" reads
#:   visually different from "found a critical threat")
SEVERITY_COLOR: dict[str, str] = {
    "HIGH": "#f85149",
    "MEDIUM": "#d29922",
    "LOW": "#e3b341",
    "INFO": "#39c5cf",
    "SAFE": "#3fb950",
    "UNKNOWN": "#a371f7",
}

#: Color used for any severity that is missing/empty/unrecognized.
#: Per the rollup contract, "we don't know" maps to the UNKNOWN color so the
#: UI never silently green-lights (or red-flags) a value it can't classify.
UNKNOWN_COLOR = SEVERITY_COLOR["UNKNOWN"]


def severity_color(severity: str) -> str:
    """Return the hex color for ``severity``.

    Falls back to :data:`UNKNOWN_COLOR` (the UNKNOWN purple) for empty or
    unrecognized labels, matching the rule applied to severity emojis in
    :mod:`mcpscanner.core.report_generator`.
    """
    if not severity:
        return UNKNOWN_COLOR
    return SEVERITY_COLOR.get(severity.upper(), UNKNOWN_COLOR)


def severity_styled(severity: str) -> str:
    """Return Rich-markup text for ``severity`` colored per :data:`SEVERITY_COLOR`."""
    return f"[bold {severity_color(severity)}]{severity}[/]"


def highest_severity(severities: Iterable[str]) -> str:
    """Roll up an iterable of severities into the single highest one.

    Thin alias for :func:`mcpscanner.core.result.get_highest_severity` so the
    TUI shares the codebase-wide rollup contract:

    - ``UNKNOWN`` is the pre-analysis default and is *displaced* by any
      concrete severity (``HIGH``/``MEDIUM``/``LOW``/``INFO``/``SAFE``).
    - When the input is empty or contains only ``UNKNOWN`` entries, the
      result is ``UNKNOWN``.
    """
    return get_highest_severity(list(severities))


__all__ = [
    "SEVERITY_COLOR",
    "UNKNOWN_COLOR",
    "highest_severity",
    "severity_color",
    "severity_styled",
]
