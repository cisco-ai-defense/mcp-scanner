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

"""Core type definitions for MCP Supply Chain analysis."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(Enum):
    """Severity levels for findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisMode(Enum):
    """Analysis modes for rules."""
    SEARCH = "search"
    TAINT = "taint"
    DATAFLOW = "dataflow"


@dataclass
class Position:
    """Source code position."""
    line: int
    column: int
    offset: int = 0


@dataclass
class Range:
    """Source code range."""
    start: Position
    end: Position


@dataclass
class MetaVariable:
    """Metavariable binding."""
    name: str
    value: Any
    range: Range


@dataclass
class Pattern:
    """Pattern definition in a rule."""
    pattern_str: str
    is_ellipsis: bool = False
    is_deep: bool = False
    metavars: list[str] = field(default_factory=list)
    metavariable_regex: dict[str, str] = field(default_factory=dict)
    metavariable_comparison: dict[str, str] = field(default_factory=dict)
    focus_metavariable: str | None = None
    label: str | None = None
    requires: str | None = None
    sanitizes_labels: set[str] = field(default_factory=set)
    not_conflicting: bool = False


@dataclass
class Propagator:
    """Custom taint propagator specification."""
    pattern: Pattern
    from_arg: str
    to_arg: str | None = None
    to_return: bool = False


@dataclass
class TaintSpec:
    """Taint analysis specification."""
    sources: list[Pattern] = field(default_factory=list)
    sinks: list[Pattern] = field(default_factory=list)
    sanitizers: list[Pattern] = field(default_factory=list)
    propagators: list[Propagator] = field(default_factory=list)


class BooleanOperator(Enum):
    """Boolean operators for pattern formulas."""
    AND = "and"
    OR = "or"
    NOT = "not"
    INSIDE = "inside"


@dataclass
class PatternFormula:
    """Boolean formula of patterns."""
    operator: BooleanOperator
    patterns: list[Pattern] = field(default_factory=list)
    subformulas: list["PatternFormula"] = field(default_factory=list)


@dataclass
class Rule:
    """Security rule definition."""
    id: str
    meta: dict[str, Any]
    mode: AnalysisMode
    languages: list[str]
    patterns: list[Pattern] = field(default_factory=list)
    taint_spec: TaintSpec | None = None
    condition: str = ""
    pattern_formula: PatternFormula | None = None
    pattern_not: list[Pattern] = field(default_factory=list)
    pattern_inside: Pattern | None = None

    @property
    def severity(self) -> Severity:
        """Get rule severity."""
        sev = self.meta.get("severity", "medium").lower()
        return Severity(sev)

    @property
    def description(self) -> str:
        """Get rule description."""
        return self.meta.get("description", "")

    @property
    def category(self) -> str:
        """Get rule category."""
        return self.meta.get("category", "security")


@dataclass
class Match:
    """A match found by a rule."""
    rule_id: str
    file_path: Path
    range: Range
    matched_code: str
    message: str
    severity: Severity
    metavars: dict[str, MetaVariable] = field(default_factory=dict)
    taint_flow: list[Range] | None = None
    fix: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert match to dictionary."""
        return {
            "rule_id": self.rule_id,
            "file": str(self.file_path),
            "start": {"line": self.range.start.line, "column": self.range.start.column},
            "end": {"line": self.range.end.line, "column": self.range.end.column},
            "matched_code": self.matched_code,
            "message": self.message,
            "severity": self.severity.value,
            "metavars": {
                name: {"value": str(mv.value), "range": self._range_to_dict(mv.range)}
                for name, mv in self.metavars.items()
            },
            "taint_flow": [self._range_to_dict(r) for r in self.taint_flow]
            if self.taint_flow
            else None,
            "fix": self.fix,
        }

    @staticmethod
    def _range_to_dict(r: Range) -> dict[str, Any]:
        """Convert range to dictionary."""
        return {
            "start": {"line": r.start.line, "column": r.start.column},
            "end": {"line": r.end.line, "column": r.end.column},
        }


@dataclass
class ScanResult:
    """Result of a scan operation."""
    matches: list[Match] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_scanned: int = 0
    rules_executed: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "matches": [m.to_dict() for m in self.matches],
            "errors": self.errors,
            "stats": {
                "files_scanned": self.files_scanned,
                "rules_executed": self.rules_executed,
                "findings": len(self.matches),
            },
        }


__all__ = [
    "Severity",
    "AnalysisMode",
    "Position",
    "Range",
    "MetaVariable",
    "Pattern",
    "Propagator",
    "TaintSpec",
    "BooleanOperator",
    "PatternFormula",
    "Rule",
    "Match",
    "ScanResult",
]
