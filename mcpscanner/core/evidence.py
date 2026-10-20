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

"""Public evidence records for MCP Scanner findings.

Analyzers attach an :class:`EvidenceRecord` while the match is still in
hand. Serializers emit that record and never reconstruct a quote, line, or
fact from legacy ``details`` prose.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..config.constants import MCPScannerConstants

MAX_MATCHED_TEXT = 240
MAX_SOURCES = 8
MAX_FACTS = 16
MAX_SUMMARY = 500

STATUS_OBSERVED = "observed"
STATUS_SCOPE_ONLY = "scope_only"
STATUS_UNAVAILABLE = "unavailable"

LOCATION_TYPES = frozenset({"mcp_field", "file", "package", "probe"})

_INT = "int"
_BOOL = "bool"
_STR = "str"
_SHA256 = "sha256"
_RFC3339 = "rfc3339"
_ROLE = "role"

# Versioned fact registry. Unknown names are dropped, never rewritten.
FACT_REGISTRY: Dict[str, str] = {
    "check.patterns_checked": _INT,
    "check.patterns_matched": _INT,
    "check.minimum_matches": _INT,
    "check.defenses_checked": _INT,
    "check.defenses_present": _INT,
    "check.timeout_present": _BOOL,
    "check.field_present": _BOOL,
    "file.sha256": _SHA256,
    "virustotal.malicious_count": _INT,
    "virustotal.suspicious_count": _INT,
    "virustotal.total_engines": _INT,
    "virustotal.scanned_at": _RFC3339,
    "package.ecosystem": _STR,
    "package.name": _STR,
    "package.version": _STR,
    "advisory.id": _STR,
    "audit.source": _STR,
    "probe.completed": _BOOL,
    "integrity.signature_header_present": _BOOL,
    "integrity.signing_capability_present": _BOOL,
    "policy.declared_count": _INT,
    "policy.allowed_count": _INT,
    "code.role": _ROLE,
    "code.symbol": _STR,
}

_CODE_ROLES = frozenset({"input", "operation", "sink"})

# Content types whose analyzed text is the original source, so a verified
# byte offset can be reported as a line. Rendered or serialized inputs stay
# at line null.
_LINE_CONTENT_TYPES = frozenset({"description", "instructions"})

_CONTENT_LOCATORS = {
    "description": "/description",
    "parameters": "/inputSchema",
    "prompt_content": "/messages/0/content",
    "prompt": "/messages/0/content",
    "arguments": "/arguments",
    "instructions": "/instructions",
    "resource_content": "/content",
    "resource": "/content",
    "text": "/description",
    "tool_definition": "",
    "comprehensive": "",
    "content": "",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_POINTER_TOKEN_RE = re.compile(r"^(?:[^\x00~/]|~0|~1)*$")


def locator_for_content_type(content_type: Optional[str]) -> str:
    """JSON Pointer for a known MCP field, or the document root."""
    return _CONTENT_LOCATORS.get(content_type or "", "")


def _limit_text(text: str, limit: int = MAX_SUMMARY) -> str:
    """Cap published text. The result is a prefix of the original string."""
    if len(text) > limit:
        return text[:limit]
    return text


def safe_matched_text(text: Optional[str]) -> Optional[str]:
    """Exact substring, capped, or null when there is no text."""
    if not isinstance(text, str) or text == "":
        return None
    return _limit_text(text, MAX_MATCHED_TEXT)


def _valid_line(line: Any) -> Optional[int]:
    if isinstance(line, bool) or not isinstance(line, int):
        return None
    if line < 1:
        return None
    return line


def _valid_locator(location_type: str, locator: str) -> bool:
    if not isinstance(locator, str) or "\n" in locator or "\r" in locator:
        return False
    if location_type == "mcp_field":
        if locator == "":
            return True
        if not locator.startswith("/") or ".." in locator.split("/"):
            return False
        for token in locator.split("/")[1:]:
            if not _POINTER_TOKEN_RE.fullmatch(token):
                return False
        return True
    if location_type == "file":
        if locator.startswith("/") or locator.startswith("\\"):
            return False
        parts = locator.replace("\\", "/").split("/")
        if any(part in ("", ".", "..") for part in parts):
            return False
        return True
    if location_type == "package":
        return 0 < len(locator) <= 200 and ".." not in locator
    if location_type == "probe":
        if "://" in locator or len(locator) > 120 or not locator:
            return False
        return True
    return False


def _coerce_fact_value(name: str, value: Any) -> Any:
    """Return a public fact value, or None when the value is not allowed."""
    kind = FACT_REGISTRY.get(name)
    if kind is None or value is None:
        return None
    if isinstance(value, (dict, list, tuple, set)):
        return None
    if kind == _BOOL:
        if isinstance(value, bool):
            return value
        return None
    if kind == _INT:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None
        return value
    if not isinstance(value, str):
        return None
    if kind == _SHA256:
        lowered = value.strip().lower()
        if not _SHA256_RE.fullmatch(lowered):
            return None
        return lowered
    if kind == _RFC3339:
        if not _RFC3339_RE.fullmatch(value.strip()):
            return None
        return value.strip()
    if kind == _ROLE:
        if value not in _CODE_ROLES:
            return None
        return value
    cleaned = _limit_text(value, MAX_MATCHED_TEXT)
    if cleaned == "":
        return None
    return cleaned


@dataclass
class EvidenceLocation:
    """Where a source sits. ``line`` is null unless the original line is known."""

    type: str
    locator: str
    line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "locator": self.locator, "line": self.line}


@dataclass
class EvidenceFact:
    """One registered observation. ``false`` is an observed negative."""

    name: str
    value: Any

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "value": self.value}


@dataclass
class EvidenceSource:
    """One location plus the verified text or facts that support it."""

    location: EvidenceLocation
    matched_text: Optional[str] = None
    facts: List[EvidenceFact] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location.to_dict(),
            "matched_text": self.matched_text,
            "facts": [fact.to_dict() for fact in self.facts],
        }

    def is_supported(self) -> bool:
        return self.matched_text is not None or bool(self.facts)


@dataclass
class EvidenceRecord:
    """Evidence for one active finding."""

    summary: str
    status: str
    sources: List[EvidenceSource] = field(default_factory=list)
    omitted_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "status": self.status,
            "sources": [source.to_dict() for source in self.sources],
            "omitted_count": self.omitted_count,
        }


def unavailable_record(summary: str) -> EvidenceRecord:
    """No verified location. Used when a producer has nothing safe to cite."""
    return EvidenceRecord(
        summary=_limit_text(summary or ""),
        status=STATUS_UNAVAILABLE,
        sources=[],
        omitted_count=0,
    )


_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _is_absolute_file_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized.startswith("/") or _WINDOWS_DRIVE_RE.match(normalized) is not None


def relative_file_locator(path: str, scan_root: Optional[str] = None) -> Optional[str]:
    """Relative file locator.

    A path under ``scan_root`` is published relative to that root, so files
    with the same name in different directories stay distinct. A relative
    path is resolved against the working directory first, so ``pkg/tools.py``
    and ``/abs/pkg/tools.py`` for the same file get the same locator.
    Other absolute paths publish only the file name.
    """
    if not isinstance(path, str) or not path:
        return None
    if scan_root:
        try:
            relative = Path(path).resolve().relative_to(Path(scan_root).resolve())
        except (OSError, ValueError):
            relative = None
        if relative is not None and _valid_locator("file", relative.as_posix()):
            return relative.as_posix()
    if _is_absolute_file_path(path):
        name = path.replace("\\", "/").rstrip("/").split("/")[-1]
        if _valid_locator("file", name):
            return name
        return None
    if _valid_locator("file", path):
        return path
    return None


def facts_record(
    summary: str,
    location_type: str,
    locator: str,
    facts: Sequence[Tuple[str, Any]],
    line: Optional[int] = None,
) -> EvidenceRecord:
    """One source supported by registered facts and no invented quote."""
    source = source_or_none(location_type, locator, None, line, facts)
    if source is None or not source.is_supported():
        return unavailable_record(summary)
    return compile_record(summary, [source])


def scope_only_record(
    summary: str,
    location_type: str,
    locator: str,
    line: Optional[int] = None,
) -> EvidenceRecord:
    """A known location with no verified substring and no facts."""
    source = source_or_none(location_type, locator, None, line, [])
    if source is None:
        return unavailable_record(summary)
    return EvidenceRecord(
        summary=_limit_text(summary or ""),
        status=STATUS_SCOPE_ONLY,
        sources=[source],
        omitted_count=0,
    )


def source_or_none(
    location_type: str,
    locator: str,
    matched_text: Optional[str],
    line: Optional[int],
    facts: Sequence[Tuple[str, Any]],
) -> Optional[EvidenceSource]:
    if (
        not isinstance(location_type, str)
        or location_type not in LOCATION_TYPES
        or not _valid_locator(location_type, locator)
    ):
        return None
    published_facts: List[EvidenceFact] = []
    seen = set()
    duplicate = False
    for name, value in facts:
        if not isinstance(name, str) or name in seen:
            duplicate = True
            break
        seen.add(name)
        coerced = _coerce_fact_value(name, value)
        if coerced is None:
            continue
        published_facts.append(EvidenceFact(name=name, value=coerced))
        if len(published_facts) >= MAX_FACTS:
            break
    published = safe_matched_text(matched_text)
    if duplicate:
        published_facts = []
    # Invalid facts are dropped. A source that offered only those facts is
    # not rewritten into a location-only claim.
    if facts and not published_facts and published is None:
        return None
    return EvidenceSource(
        location=EvidenceLocation(
            type=location_type,
            locator=locator,
            line=_valid_line(line),
        ),
        matched_text=published,
        facts=published_facts,
    )


def _is_negative_check(source: EvidenceSource) -> bool:
    return any(fact.value is False for fact in source.facts)


def compile_record(
    summary: str,
    sources: Sequence[EvidenceSource],
    omitted_count: int = 0,
) -> EvidenceRecord:
    """Apply caps and derive status from what each source can actually show."""
    kept: List[EvidenceSource] = []
    for source in sources:
        if source.location.type not in LOCATION_TYPES:
            continue
        if not _valid_locator(source.location.type, source.location.locator):
            continue
        kept.append(source)

    extra = 0
    if len(kept) > MAX_SOURCES:
        negatives = [source for source in kept if _is_negative_check(source)]
        others = [source for source in kept if not _is_negative_check(source)]
        if len(negatives) >= MAX_SOURCES:
            selected = negatives[:MAX_SOURCES]
        else:
            room = MAX_SOURCES - len(negatives)
            selected = negatives + others[:room]
        extra = len(kept) - len(selected)
        kept = selected

    base_omitted = (
        omitted_count if isinstance(omitted_count, int) and omitted_count >= 0 else 0
    )
    if not kept:
        return unavailable_record(summary)

    if all(source.is_supported() for source in kept):
        status = STATUS_OBSERVED
    elif all(not source.is_supported() for source in kept):
        status = STATUS_SCOPE_ONLY
    else:
        supported = [source for source in kept if source.is_supported()]
        extra += len(kept) - len(supported)
        kept = supported
        status = STATUS_OBSERVED if kept else STATUS_SCOPE_ONLY

    if status == STATUS_UNAVAILABLE:
        return unavailable_record(summary)

    return EvidenceRecord(
        summary=_limit_text(summary or ""),
        status=status,
        sources=kept,
        omitted_count=base_omitted + extra,
    )


def render_evidence(evidence: Any, summary: str) -> Dict[str, Any]:
    """Public dict for a producer record. Invalid input becomes unavailable."""
    if isinstance(evidence, EvidenceRecord):
        rendered = compile_record(
            evidence.summary or summary,
            evidence.sources,
            evidence.omitted_count,
        )
        return rendered.to_dict()
    if isinstance(evidence, dict):
        return _render_mapping(evidence, summary)
    return unavailable_record(summary).to_dict()


def _render_mapping(payload: Dict[str, Any], summary: str) -> Dict[str, Any]:
    raw_sources = payload.get("sources")
    if not isinstance(raw_sources, list):
        return unavailable_record(summary).to_dict()
    sources: List[EvidenceSource] = []
    for item in raw_sources:
        if not isinstance(item, dict):
            continue
        location = item.get("location")
        if not isinstance(location, dict):
            continue
        fact_pairs: List[Tuple[str, Any]] = []
        raw_facts = item.get("facts") or []
        if isinstance(raw_facts, list):
            for fact in raw_facts:
                if isinstance(fact, dict) and "name" in fact:
                    fact_pairs.append((fact.get("name"), fact.get("value")))
        source = source_or_none(
            location.get("type"),
            location.get("locator"),
            item.get("matched_text"),
            location.get("line"),
            fact_pairs,
        )
        if source is not None:
            sources.append(source)
    omitted = payload.get("omitted_count", 0)
    record_summary = (
        payload.get("summary") if isinstance(payload.get("summary"), str) else summary
    )
    return compile_record(
        record_summary, sources, omitted if isinstance(omitted, int) else 0
    ).to_dict()


def public_evidence_for_finding(finding: Any) -> Dict[str, Any]:
    """One evidence object for a finding.

    Missing evidence stays ``unavailable``. Legacy ``details['evidence']``
    prose is not copied into ``matched_text``.
    """
    if isinstance(finding, dict):
        summary = finding.get("summary") or ""
        evidence = finding.get("evidence")
    else:
        summary = getattr(finding, "summary", "") or ""
        evidence = getattr(finding, "evidence", None)
    if evidence is None:
        return unavailable_record(summary).to_dict()
    return render_evidence(evidence, summary)


def public_evidence_for_findings(findings: Iterable[Any]) -> List[Dict[str, Any]]:
    """One record per finding, in the order the findings are retained."""
    return [public_evidence_for_finding(finding) for finding in findings]


def raw_finding_payload(finding: Any) -> Dict[str, Any]:
    """Per-finding CLI record with the same evidence object as the rollup."""
    details = dict(getattr(finding, "details", None) or {})
    details.pop("raw_response", None)
    limited_details: Dict[str, Any] = {}
    for key, value in details.items():
        if isinstance(value, str):
            limited_details[key] = _limit_text(value)
        else:
            limited_details[key] = value
    taxonomy = getattr(finding, "mcp_taxonomy", None)
    return {
        "severity": finding.severity,
        "summary": _limit_text(finding.summary or ""),
        "analyzer": finding.analyzer,
        "details": limited_details,
        "mcp_taxonomy": taxonomy,
        "evidence": public_evidence_for_finding(finding),
    }


def prepare_behavioral_evidence(
    threat_name: str,
    analysis: Any,
    func_context: Any,
    file_path: Optional[str],
    *,
    allow_flow_roles: bool,
    scan_root: Optional[str] = None,
) -> Tuple[str, EvidenceRecord]:
    """Summary and evidence for one behavioral finding.

    The model's reason replaces the summary only when parameter-flow data
    already computed by the scanner links a verified input quote to a
    verified sink. Otherwise the summary keeps the line number and the
    description-versus-behavior comparison. JavaScript and TypeScript pass
    ``allow_flow_roles=False`` so a cited operation can be located without
    claiming that flow.
    """
    analysis = analysis if isinstance(analysis, dict) else {}
    function_name = getattr(func_context, "name", None)
    if not isinstance(function_name, str) or not function_name.strip():
        function_name = "function"
    else:
        function_name = function_name.strip()
    file_path = file_path if isinstance(file_path, str) else None
    scan_root = scan_root if isinstance(scan_root, str) and scan_root else None
    operations = _verified_operations(analysis, func_context, file_path, scan_root)
    flow_ok = allow_flow_roles and _flow_links_input_to_sink(func_context, operations)
    summary = _behavioral_summary(
        threat_name,
        function_name,
        analysis,
        flow_ok,
        _valid_line(getattr(func_context, "line_number", None)),
    )
    record = _behavioral_record(
        summary,
        function_name,
        func_context,
        file_path,
        operations,
        allow_flow_roles,
        scan_root,
    )
    return summary, record


def behavioral_evidence_from_context(
    summary: str,
    analysis: Any,
    func_context: Any,
    file_path: Optional[str],
) -> EvidenceRecord:
    """Evidence for a caller that already chose the public summary."""
    _summary, record = prepare_behavioral_evidence(
        "",
        analysis,
        func_context,
        file_path,
        allow_flow_roles=str(file_path).endswith(".py"),
    )
    record.summary = _limit_text(summary or record.summary)
    return record


def incomplete_location_evidence(
    summary: str,
    file_path: Optional[str],
    line_number: Any,
    scan_root: Optional[str] = None,
) -> EvidenceRecord:
    """The function was located, and the check did not finish."""
    locator = relative_file_locator(file_path or "", scan_root)
    if locator is None:
        return unavailable_record(summary)
    return scope_only_record(summary, "file", locator, _valid_line(line_number))


def _behavioral_summary(
    threat_name: str,
    function_name: str,
    analysis: Dict[str, Any],
    flow_ok: bool,
    line: Optional[int],
) -> str:
    reason = analysis.get("reason") or analysis.get("summary")
    if flow_ok and isinstance(reason, str) and reason.strip():
        return reason.strip()
    label = threat_name.strip() if isinstance(threat_name, str) and threat_name.strip() else "mismatch"
    line_info = f"Line {line}: " if line is not None else ""
    claims = analysis.get("description_claims")
    behavior = analysis.get("actual_behavior")
    if (
        isinstance(claims, str)
        and claims.strip()
        and isinstance(behavior, str)
        and behavior.strip()
    ):
        return _limit_text(
            f"{line_info}{label} - Description claims: '{claims.strip()}' | "
            f"Actual behavior: {behavior.strip()}"
        )
    return f"{line_info}{label} in {function_name}"


def _behavioral_record(
    summary: str,
    function_name: str,
    func_context: Any,
    file_path: Optional[str],
    operations: List[Dict[str, Any]],
    allow_flow_roles: bool,
    scan_root: Optional[str] = None,
) -> EvidenceRecord:
    if not operations:
        locator = relative_file_locator(file_path or "", scan_root)
        if locator is None:
            return unavailable_record(summary)
        line = _valid_line(getattr(func_context, "line_number", None))
        source = source_or_none(
            "file", locator, None, line, [("code.symbol", function_name)]
        )
        if source is None:
            return unavailable_record(summary)
        return compile_record(summary, [source])
    sources: List[EvidenceSource] = []
    for operation in operations:
        role = _supported_role(
            operation.get("role"),
            operation.get("quote") or "",
            func_context,
            allow_flow_roles,
            operation.get("line") is not None,
        )
        facts: List[Tuple[str, Any]] = [("code.symbol", function_name)]
        if role:
            facts.append(("code.role", role))
        source = source_or_none(
            "file",
            operation["locator"],
            operation.get("quote"),
            operation.get("line"),
            facts,
        )
        if source is not None:
            sources.append(source)
    if not sources:
        return unavailable_record(summary)
    return compile_record(summary, sources)


def _verified_operations(
    analysis: Dict[str, Any],
    func_context: Any,
    file_path: Optional[str],
    scan_root: Optional[str] = None,
) -> List[Dict[str, Any]]:
    raw_ops = analysis.get("operations")
    candidates: List[Dict[str, Any]] = []
    if isinstance(raw_ops, list):
        candidates.extend(item for item in raw_ops if isinstance(item, dict))
    elif isinstance(analysis.get("source_quote"), str):
        candidates.append({"quote": analysis["source_quote"], "role": "operation"})
    extra_paths = _cross_file_paths(func_context)
    verified: List[Dict[str, Any]] = []
    seen = set()
    for operation in candidates:
        quote = operation.get("quote")
        if not isinstance(quote, str) or not quote.strip():
            continue
        hint = operation.get("line_hint")
        paths = []
        hinted_path = _allowed_hinted_path(
            operation.get("file"), file_path, extra_paths, scan_root
        )
        if hinted_path:
            paths.append(hinted_path)
        if file_path:
            paths.append(file_path)
        paths.extend(extra_paths)
        for path in paths:
            located = _locate_quote_in_file(path, quote, hint, scan_root)
            if located is None:
                continue
            key = (located["locator"], located["line"], quote)
            if key in seen:
                continue
            seen.add(key)
            verified.append(
                {
                    "quote": quote,
                    "line": located["line"],
                    "locator": located["locator"],
                    "role": operation.get("role"),
                }
            )
    return verified


def _allowed_hinted_path(
    hinted: Any,
    file_path: Optional[str],
    extra_paths: List[str],
    scan_root: Optional[str],
) -> Optional[str]:
    """A model-supplied file path, kept only inside the scanned code.

    With a scan root, the path must resolve under it. Without one, it must
    be the scanned file or a cross-file path the call graph already found.
    """
    if not isinstance(hinted, str) or not hinted.strip():
        return None
    try:
        if scan_root:
            root = Path(scan_root).resolve()
            candidate = Path(hinted)
            if not candidate.is_absolute():
                candidate = root / candidate
            resolved = candidate.resolve()
            resolved.relative_to(root)
            return str(resolved)
        resolved = Path(hinted).resolve()
        for known in [file_path, *extra_paths]:
            if known and Path(known).resolve() == resolved:
                return known
    except (OSError, ValueError):
        return None
    return None


def _locate_quote_in_file(
    path: str, quote: str, line_hint: Any, scan_root: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    text = _read_original_source(path)
    if text is None or quote not in text:
        return None
    locator = relative_file_locator(path, scan_root)
    if locator is None:
        return None
    lines = _quote_line_numbers(text, quote)
    hint = line_hint if isinstance(line_hint, int) and not isinstance(line_hint, bool) else None
    if hint in lines:
        line: Optional[int] = hint
    elif len(lines) == 1:
        line = lines[0]
    else:
        line = None
    return {"locator": locator, "line": line}


def _quote_line_numbers(text: str, quote: str) -> List[int]:
    lines: List[int] = []
    start = 0
    while True:
        index = text.find(quote, start)
        if index < 0:
            return lines
        lines.append(text.count("\n", 0, index) + 1)
        start = index + max(len(quote), 1)


def _read_original_source(path: str) -> Optional[str]:
    if not isinstance(path, str) or not path:
        return None
    try:
        candidate = Path(path)
        if candidate.is_symlink() or not candidate.is_file():
            return None
        if candidate.stat().st_size > MCPScannerConstants.MAX_FILE_SIZE_BYTES * 5:
            return None
        return candidate.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def _scanner_file_locator(path: str) -> Optional[str]:
    """Public file locator. Absolute paths publish only the file name."""
    return relative_file_locator(path)


def _cross_file_paths(func_context: Any) -> List[str]:
    calls = getattr(func_context, "cross_file_calls", None)
    if not isinstance(calls, list):
        return []
    paths: List[str] = []
    for call in calls:
        if not isinstance(call, dict):
            continue
        for key in ("to_file", "from_file", "file"):
            value = call.get(key)
            if isinstance(value, str) and value and value not in paths:
                paths.append(value)
    return paths


def _flow_links_input_to_sink(func_context: Any, operations: List[Dict[str, Any]]) -> bool:
    inputs = [op for op in operations if op.get("role") == "input"]
    sinks = [op for op in operations if op.get("role") == "sink"]
    if not inputs or not sinks:
        return False
    for flow in _parameter_flows(func_context):
        if not flow.get("reaches_external"):
            continue
        parameter = flow.get("parameter_name")
        if not isinstance(parameter, str) or not parameter:
            continue
        if not any(_token_in_quote(parameter, op.get("quote") or "") for op in inputs):
            continue
        calls = flow.get("reaches_calls") or []
        for call in calls:
            if isinstance(call, str) and any(
                call and _token_in_quote(call, op.get("quote") or "") for op in sinks
            ):
                return True
    return False


def _supported_role(
    role: Any,
    quote: str,
    func_context: Any,
    allow_flow_roles: bool,
    line_verified: bool,
) -> Optional[str]:
    if role not in _CODE_ROLES or not line_verified:
        return None
    if role == "operation":
        if _call_named_in_quote(func_context, quote) or not allow_flow_roles:
            return "operation"
        return None
    if not allow_flow_roles:
        return None
    if role == "input" and _parameter_named_in_quote(func_context, quote):
        return "input"
    if role == "sink" and _sink_call_supported(func_context, quote):
        return "sink"
    return None


def _parameter_flows(func_context: Any) -> List[Dict[str, Any]]:
    flows = getattr(func_context, "parameter_flows", None)
    if not isinstance(flows, list):
        return []
    return [flow for flow in flows if isinstance(flow, dict)]


def _parameter_named_in_quote(func_context: Any, quote: str) -> bool:
    for flow in _parameter_flows(func_context):
        name = flow.get("parameter_name")
        if isinstance(name, str) and _token_in_quote(name, quote):
            return True
    parameters = getattr(func_context, "parameters", None)
    if isinstance(parameters, list):
        for parameter in parameters:
            name = parameter.get("name") if isinstance(parameter, dict) else None
            if isinstance(name, str) and _token_in_quote(name, quote):
                return True
    return False


def _sink_call_supported(func_context: Any, quote: str) -> bool:
    for flow in _parameter_flows(func_context):
        if not flow.get("reaches_external"):
            continue
        for call in flow.get("reaches_calls") or []:
            if isinstance(call, str) and call and _token_in_quote(call, quote):
                return True
    return False


def _call_named_in_quote(func_context: Any, quote: str) -> bool:
    calls = getattr(func_context, "function_calls", None)
    if not isinstance(calls, list):
        return False
    for call in calls:
        name = call.get("name") if isinstance(call, dict) else None
        if isinstance(name, str) and name and _token_in_quote(name, quote):
            return True
    return False


def _token_in_quote(token: str, quote: str) -> bool:
    if not token or not quote:
        return False
    return re.search(r"(?<!\w)" + re.escape(token) + r"(?!\w)", quote) is not None


def llm_threat_evidence(
    summary: str,
    citation: Any,
    fields: Optional[Dict[str, Any]],
    entity_kind: str,
    consumed_quotes: set,
) -> EvidenceRecord:
    """Verify each citation. A quote already used by another threat is omitted."""
    citations = citation if isinstance(citation, list) else [citation]
    sources: List[EvidenceSource] = []
    for item in citations:
        if not isinstance(item, dict):
            continue
        quote = item.get("quote")
        if not isinstance(quote, str) or not quote or quote in consumed_quotes:
            continue
        located = _llm_quote_locations(quote, item.get("field_hint") or item.get("field"), fields, entity_kind)
        if not located:
            continue
        consumed_quotes.add(quote)
        for locator, line in located:
            source = source_or_none("mcp_field", locator, quote, line, [])
            if source is not None and source.is_supported():
                sources.append(source)
    if sources:
        return compile_record(summary, sources)
    locator = _scope_locator(fields, entity_kind)
    if locator is None:
        return unavailable_record(summary)
    return scope_only_record(summary, "mcp_field", locator)


def _llm_quote_locations(
    quote: str,
    hint: Any,
    fields: Optional[Dict[str, Any]],
    entity_kind: str,
) -> List[Tuple[str, Optional[int]]]:
    """Every verified location of ``quote``. A hint selects none by itself."""
    fields = fields or {}
    found: List[Tuple[str, Optional[int]]] = []
    seen = set()

    def add(locator: str, line: Optional[int]) -> None:
        if locator in seen or not _valid_locator("mcp_field", locator):
            return
        seen.add(locator)
        found.append((locator, line))

    description = fields.get("description")
    if isinstance(description, str) and quote in description:
        add("/description", description.count("\n", 0, description.find(quote)) + 1)
    name = fields.get("name")
    if isinstance(name, str) and quote in name:
        add("/name", None)
    instructions = fields.get("instructions")
    if isinstance(instructions, str) and quote in instructions:
        add("/instructions", instructions.count("\n", 0, instructions.find(quote)) + 1)
    body = fields.get("body")
    if isinstance(body, str) and quote in body:
        locator, _publish = _llm_field_location("body", entity_kind)
        add(locator, None)
    arguments = fields.get("arguments")
    if arguments is not None:
        argument_pointers: List[str] = []
        _walk_parameter_value(arguments, ["arguments"], quote, argument_pointers)
        for locator in argument_pointers:
            add(locator, None)
    for locator in _parameter_pointers(fields.get("parameters"), quote):
        add(locator, None)
    hint_pointer = hint.strip() if isinstance(hint, str) else ""
    if hint_pointer in {"description", "parameters", "body", "name", "instructions"}:
        hint_pointer, _publish = _llm_field_location(hint_pointer, entity_kind)
    specific = any(locator.startswith(hint_pointer + "/") for locator in seen)
    if (
        hint_pointer
        and not specific
        and _valid_locator("mcp_field", hint_pointer)
        and hint_pointer not in seen
        and _hint_contains_quote(hint_pointer, quote, fields, entity_kind)
    ):
        add(hint_pointer, None)
    return found


def _hint_contains_quote(
    pointer: str, quote: str, fields: Dict[str, Any], entity_kind: str
) -> bool:
    if pointer == "/description":
        text = fields.get("description")
        return isinstance(text, str) and quote in text
    if pointer == "/name":
        text = fields.get("name")
        return isinstance(text, str) and quote in text
    if pointer == "/instructions":
        text = fields.get("instructions")
        return isinstance(text, str) and quote in text
    body_locator, _publish = _llm_field_location("body", entity_kind)
    if pointer == body_locator:
        text = fields.get("body")
        return isinstance(text, str) and quote in text
    if pointer.startswith("/inputSchema/"):
        return pointer in _parameter_pointers(fields.get("parameters"), quote)
    if pointer == "/arguments" or pointer.startswith("/arguments/"):
        pointers: List[str] = []
        _walk_parameter_value(fields.get("arguments"), ["arguments"], quote, pointers)
        return pointer in pointers
    return False


def _parameter_pointers(parameters: Any, quote: str) -> List[str]:
    """Property pointers that contain ``quote``. A dumped schema is not a location."""
    if not isinstance(parameters, dict):
        return []
    pointers: List[str] = []
    if isinstance(parameters.get("properties"), dict):
        _walk_parameter_value(parameters, ["inputSchema"], quote, pointers)
    else:
        _walk_parameter_value(parameters, ["inputSchema", "properties"], quote, pointers)
    return pointers


def _walk_parameter_value(
    value: Any, parts: List[str], quote: str, pointers: List[str]
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                continue
            child_parts = parts + [key]
            if key == quote:
                pointer = _json_pointer(child_parts)
                if pointer not in pointers:
                    pointers.append(pointer)
            _walk_parameter_value(child, child_parts, quote, pointers)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _walk_parameter_value(child, parts + [str(index)], quote, pointers)
        return
    if isinstance(value, str) and quote in value and parts:
        pointer = _json_pointer(parts)
        if pointer not in pointers:
            pointers.append(pointer)


def _json_pointer(parts: Sequence[str]) -> str:
    escaped = [part.replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped)


def _scope_locator(fields: Optional[Dict[str, Any]], entity_kind: str) -> Optional[str]:
    fields = fields or {}
    if isinstance(fields.get("description"), str) and fields.get("description"):
        return "/description"
    if isinstance(fields.get("body"), str) and fields.get("body"):
        locator, _publish = _llm_field_location("body", entity_kind)
        return locator
    if fields.get("parameters"):
        return "/inputSchema"
    if fields.get("arguments") is not None:
        return "/arguments"
    if isinstance(fields.get("instructions"), str) and fields.get("instructions"):
        return "/instructions"
    if isinstance(fields.get("name"), str) and fields.get("name"):
        return "/name"
    return None


def _llm_field_location(field_name: str, entity_kind: str) -> Tuple[str, bool]:
    if field_name == "description":
        return "/description", True
    if field_name == "parameters":
        return "/inputSchema", False
    if field_name == "name":
        return "/name", False
    if field_name == "instructions":
        return "/instructions", True
    if field_name == "body":
        if entity_kind == "prompt":
            return "/messages/0/content", False
        return "/content", False
    return "", False


def yara_evidence_record(
    content: str,
    match: Any,
    content_type: Optional[str],
    summary: str,
) -> EvidenceRecord:
    """Build evidence from YARA string instances still attached to ``match``.

    Rule names and ``$`` string identifiers stay internal. A hit in
    serialized parameters keeps ``line`` null.
    """
    default_locator = locator_for_content_type(content_type)
    publish_line = (content_type or "") in _LINE_CONTENT_TYPES
    sources: List[EvidenceSource] = []
    seen = set()

    for text, offset in _iter_yara_instances(match):
        verified, line = _verify_span(content or "", text, offset, publish_line)
        if verified is None:
            continue
        published = safe_matched_text(verified)
        if published is None:
            continue
        locator = _yara_match_locator(content or "", content_type, published, default_locator)
        key = (locator, line, published)
        if key in seen:
            continue
        seen.add(key)
        source = source_or_none("mcp_field", locator, published, line, [])
        if source is not None:
            sources.append(source)

    if sources:
        return compile_record(summary, sources, 0)
    return scope_only_record(summary, "mcp_field", default_locator)


def _yara_match_locator(
    content: str, content_type: Optional[str], matched: str, default: str
) -> str:
    """Cite a parameter hit on the JSON field that actually contains it.

    The parameters scan is the tool object with the description removed, so
    a match in the tool name is not an ``/inputSchema`` quote.
    """
    if content_type != "parameters":
        return default
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return default
    if not isinstance(data, dict):
        return default
    schema = data.get("inputSchema")
    if isinstance(schema, (dict, list)) and matched in json.dumps(schema):
        return "/inputSchema"
    if "inputSchema" not in data and "name" not in data:
        return "/inputSchema"
    name = data.get("name")
    if isinstance(name, str) and matched in name:
        return "/name"
    for key, value in data.items():
        if key in ("inputSchema", "description"):
            continue
        rendered = value if isinstance(value, str) else json.dumps(value)
        if isinstance(rendered, str) and matched in rendered:
            return "/" + key.replace("~", "~0").replace("/", "~1")
    return ""


def _yara_strings(match: Any) -> list:
    strings = getattr(match, "strings", None)
    if isinstance(strings, (list, tuple)):
        return list(strings)
    return []


def _iter_yara_instances(match: Any) -> Iterable[Tuple[str, Optional[int]]]:
    strings = _yara_strings(match)
    for item in strings:
        instances = getattr(item, "instances", None)
        if instances is not None:
            for instance in instances:
                data = getattr(instance, "matched_data", b"")
                text = _decode_match(data)
                if text is None:
                    continue
                offset = getattr(instance, "offset", None)
                yield text, offset if isinstance(offset, int) else None
            continue
        if isinstance(item, tuple) and len(item) >= 3:
            offset, _identifier, data = item[0], item[1], item[2]
            text = _decode_match(data)
            if text is None:
                continue
            yield text, offset if isinstance(offset, int) else None


def _decode_match(data: Any) -> Optional[str]:
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
    elif isinstance(data, str):
        text = data
    else:
        return None
    if text == "" or "\ufffd" in text:
        return None
    return text


def _verify_span(
    content: str,
    text: str,
    offset: Optional[int],
    publish_line: bool,
) -> Tuple[Optional[str], Optional[int]]:
    """Keep the instance only when it is an exact substring of the input."""
    if text not in content:
        return None, None
    line = None
    if publish_line and isinstance(offset, int) and offset >= 0:
        encoded = content.encode("utf-8")
        if offset <= len(encoded):
            try:
                prefix = encoded[:offset].decode("utf-8")
            except UnicodeDecodeError:
                prefix = None
            if prefix is not None and content.startswith(text, len(prefix)):
                line = prefix.count("\n") + 1
    return text, line
