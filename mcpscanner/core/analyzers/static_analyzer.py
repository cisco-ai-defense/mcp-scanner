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

"""Static File Analyzer module for MCP Scanner SDK.

This module contains the static analyzer for scanning pre-generated MCP JSON files
without connecting to a live server. Useful for CI/CD pipelines and offline scanning.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .base import BaseAnalyzer, SecurityFinding
from .schema_reference_analyzer import SchemaReferenceAnalyzer
from ..models import AnalyzerEnum
from ...utils.logging_config import get_logger

logger = get_logger(__name__)


def _normalize_mime_type(mime: Optional[str]) -> str:
    """Base MIME type, lowercased, without parameters.

    Same rule as ``Scanner._normalize_mime_type`` on the remote path, so
    ``text/html;profile=mcp-app`` (MCP Apps UI resources) matches a
    ``text/html`` allowlist entry here too instead of being skipped.
    """
    if not mime:
        return ""
    return mime.split(";", 1)[0].strip().lower()


def _extract_html_text_if_needed(content: str, mime_type: Optional[str]) -> str:
    """Strip HTML tags from a resource body when ``mime_type`` is ``text/html``.

    H5 fix: the remote scan path (``Scanner._analyze_resource``)
    already runs BeautifulSoup on ``text/html`` resources before
    passing the body to API/LLM analyzers and persisting it in
    ``ResourceScanResult.resource_text``. The static path used to
    skip this step, so the same resource scanned via two paths
    produced two different ``resource_text`` shapes — and therefore
    two different meta-analyzer prompts when ``--enable-meta`` ran.

    Keeping the helper module-level (rather than inside ``StaticAnalyzer``)
    so a future reviewer who needs to make the two paths byte-equal
    can lift the remote path's inline copy onto this helper too.

    BeautifulSoup is an optional dependency; if it's unavailable, fall
    back to the raw content with a single warning per import failure
    (matches the remote path's exact behaviour).
    """
    if _normalize_mime_type(mime_type) != "text/html" or not content:
        return content
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        logger.warning(
            "BeautifulSoup not installed; static-path HTML resource will "
            "be analysed (and surfaced in resource_text) as raw markup. "
            "Install bs4 to match the remote-path behaviour."
        )
        return content
    try:
        soup = BeautifulSoup(content, "html.parser")
        return soup.get_text(separator="\n", strip=True)
    except (ValueError, TypeError) as e:
        logger.warning(
            "Static-path HTML extraction failed (%s); using raw content. "
            "resource_text will diverge from remote-path output for this "
            "resource.",
            e,
        )
        return content
    except Exception as e:  # pragma: no cover - defensive parity with remote path
        logger.error(
            "Unexpected error in static-path HTML extraction (%s); using "
            "raw content.",
            e,
        )
        return content


class StaticAnalyzer:
    """Analyzer for scanning pre-generated MCP JSON files.

    This analyzer reads static JSON files containing MCP tools, prompts, or resources
    and coordinates scanning using the provided sub-analyzers (YARA, LLM, API).

    This is NOT a security analyzer itself - it's a coordinator that:
    1. Reads static JSON files
    2. Parses MCP protocol structures
    3. Delegates actual security analysis to other analyzers

    Example:
        >>> from mcpscanner import Config
        >>> from mcpscanner.core.analyzers import StaticAnalyzer, YaraAnalyzer
        >>>
        >>> yara = YaraAnalyzer()
        >>> static = StaticAnalyzer(analyzers=[yara])
        >>>
        >>> results = await static.scan_tools_file("tools-list.json")
        >>> for result in results:
        ...     print(f"Tool: {result.tool_name}, Safe: {result.is_safe}")
    """

    def __init__(
        self,
        analyzers: Optional[List[BaseAnalyzer]] = None,
        config: Optional[Any] = None,
    ):
        """Initialize a new StaticAnalyzer instance.

        Args:
            analyzers: List of analyzer instances to use for scanning.
            config: Optional configuration object (for future use).
        """
        self.analyzers = analyzers or []
        self.config = config

    def _load_json_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Load and parse a JSON file.

        Args:
            file_path: Path to the JSON file.

        Returns:
            Dict[str, Any]: Parsed JSON content.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            json.JSONDecodeError: If the file contains invalid JSON.
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                raise json.JSONDecodeError(
                    f"Invalid JSON in {file_path}: {e.msg}", e.doc, e.pos
                )

    @staticmethod
    def _get_finding_analyzer_name(analyzer) -> str:
        """Get the analyzer name as used in SecurityFinding.analyzer field.

        BaseAnalyzer subclasses may set self.name differently from the value
        they write into finding.analyzer. This mapping ensures the names
        reported in result.analyzers match the finding-level names so the
        report generator groups them correctly.
        """
        name_map = {
            "LLMAnalyzer": "LLM",
        }
        return name_map.get(analyzer.name, analyzer.name)

    async def _analyze_content(
        self,
        content: str,
        context: Optional[Dict[str, Any]] = None,
        analyzers: Optional[List[BaseAnalyzer]] = None,
        outcome: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityFinding]:
        """Run all configured analyzers on the content.

        Args:
            content: Content to analyze.
            context: Additional context for analysis.
            analyzers: Optional subset of configured analyzers for this content.
            outcome: Optional per-item collector for successes and failures.

        Returns:
            List[SecurityFinding]: Combined findings from all analyzers.
        """
        all_findings = []

        for analyzer in self.analyzers if analyzers is None else analyzers:
            analyzer_name = self._get_finding_analyzer_name(analyzer)
            try:
                findings = await analyzer.analyze(content, context)
                all_findings.extend(findings)
                if outcome is not None and analyzer_name not in outcome["analyzers"]:
                    outcome["analyzers"].append(analyzer_name)
            except Exception as e:
                # Provider exceptions may contain credentials or scanned text.
                # Record only the exception type in user-visible results/logs.
                error_type = type(e).__name__
                content_type = str((context or {}).get("content_type", "content"))
                if outcome is not None:
                    outcome["analyzer_errors"].append(
                        {
                            "analyzer": analyzer_name,
                            "content_type": content_type,
                            "message": f"{error_type} during analysis",
                        }
                    )
                logger.error(
                    "%s analysis failed on %s: %s",
                    analyzer_name,
                    content_type,
                    error_type,
                )

        return all_findings

    async def _inspect_schema_references(
        self,
        params_json: str,
        params_context: Dict[str, Any],
        all_findings: List[SecurityFinding],
        outcome: Dict[str, Any],
    ) -> None:
        """Classify schema $ref values when the caller did not select SCHEMA.

        The reference string is inspected locally and is never fetched.
        """
        try:
            schema_findings = await SchemaReferenceAnalyzer().analyze(
                params_json, params_context
            )
        except Exception as error:
            error_type = type(error).__name__
            outcome["analyzer_errors"].append(
                {
                    "analyzer": "SCHEMA",
                    "content_type": "parameters",
                    "message": f"{error_type} during analysis",
                }
            )
            logger.error(
                "SCHEMA analysis failed on parameters: %s",
                error_type,
            )
            return
        all_findings.extend(schema_findings)
        if schema_findings and "SCHEMA" not in outcome["analyzers"]:
            outcome["analyzers"].append("SCHEMA")

    @staticmethod
    def _scan_outcome(
        findings: List[SecurityFinding], outcome: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Complete a static item without treating analyzer failure as safe."""
        errors = outcome["analyzer_errors"]
        successful = outcome["analyzers"]
        if errors:
            status = "partial" if successful else "failed"
        else:
            status = "completed" if successful else "skipped"
        is_safe = False if findings else True if status == "completed" else None
        return {
            "is_safe": is_safe,
            "status": status,
            "analyzers": successful,
            "analyzer_errors": errors,
        }

    async def scan_tools_file(
        self, file_path: Union[str, Path]
    ) -> List[Dict[str, Any]]:
        """Scan a JSON file containing MCP tools/list output.

        Expected JSON format:
        {
          "tools": [
            {
              "name": "tool_name",
              "description": "Tool description",
              "inputSchema": {...}
            }
          ]
        }

        Args:
            file_path: Path to the tools JSON file.

        Returns:
            List[Dict]: List of scan results with structure:
                {
                    "tool_name": str,
                    "tool_description": str,
                    "is_safe": bool,
                    "findings": List[SecurityFinding],
                    "status": str
                }

        Raises:
            FileNotFoundError: If file doesn't exist.
            json.JSONDecodeError: If file contains invalid JSON.
            ValueError: If JSON structure is invalid.
        """
        data = self._load_json_file(file_path)

        if "tools" not in data:
            raise ValueError(f"Invalid tools file: missing 'tools' key in {file_path}")

        if not isinstance(data["tools"], list):
            raise ValueError(
                f"Invalid tools file: 'tools' must be an array in {file_path}"
            )

        results = []

        for tool_data in data["tools"]:
            tool_name = tool_data.get("name", "unknown")
            tool_description = tool_data.get("description", "")
            if tool_description is not None and not isinstance(tool_description, str):
                try:
                    tool_description = json.dumps(tool_description)
                except (TypeError, ValueError):
                    tool_description = ""

            all_findings = []
            outcome: Dict[str, Any] = {"analyzers": [], "analyzer_errors": []}

            # Analyze description
            if tool_description:
                desc_context = {"tool_name": tool_name, "content_type": "description"}
                desc_findings = await self._analyze_content(
                    tool_description, desc_context, outcome=outcome
                )
                all_findings.extend(desc_findings)

            # Name, schemas, title, annotations, and any other advertised
            # field are tool content, even when no schema key is present.
            # Reference strings are classified locally and never fetched.
            params_data = {
                key: value
                for key, value in tool_data.items()
                if key != "description"
            }
            advertised_text = ""
            if params_data:
                params_json = json.dumps(params_data)
                advertised_text = params_json

                params_context = {"tool_name": tool_name, "content_type": "parameters"}
                params_analyzers = None
                params_findings = await self._analyze_content(
                    params_json,
                    params_context,
                    analyzers=params_analyzers,
                    outcome=outcome,
                )
                all_findings.extend(params_findings)
                selected = (
                    self.analyzers if params_analyzers is None else params_analyzers
                )
                if not any(
                    isinstance(analyzer, SchemaReferenceAnalyzer)
                    for analyzer in selected
                ):
                    await self._inspect_schema_references(
                        params_json, params_context, all_findings, outcome
                    )

            result = {
                "tool_name": tool_name,
                "tool_description": tool_description,
                "advertised_text": advertised_text,
                "findings": all_findings,
                **self._scan_outcome(all_findings, outcome),
            }
            # Analyzers still see an output-only schema, so a real threat is
            # reported. No findings stays "not assessed": a plain output
            # schema used to be skipped, and a rule that does not match it
            # is not a clean bill of health.
            output_only = (
                not tool_description
                and "inputSchema" not in tool_data
                and "outputSchema" in tool_data
            )
            if output_only and not all_findings and not outcome["analyzer_errors"]:
                result["is_safe"] = None
                result["status"] = "skipped"
                result["analyzers"] = []

            results.append(result)

        return results

    async def scan_prompts_file(
        self, file_path: Union[str, Path]
    ) -> List[Dict[str, Any]]:
        """Scan a JSON file containing MCP prompts/list output.

        Expected JSON format:
        {
          "prompts": [
            {
              "name": "prompt_name",
              "description": "Prompt description",
              "arguments": [...]
            }
          ]
        }

        Args:
            file_path: Path to the prompts JSON file.

        Returns:
            List[Dict]: List of scan results.

        Raises:
            FileNotFoundError: If file doesn't exist.
            json.JSONDecodeError: If file contains invalid JSON.
            ValueError: If JSON structure is invalid.
        """
        data = self._load_json_file(file_path)

        if "prompts" not in data:
            raise ValueError(
                f"Invalid prompts file: missing 'prompts' key in {file_path}"
            )

        if not isinstance(data["prompts"], list):
            raise ValueError(
                f"Invalid prompts file: 'prompts' must be an array in {file_path}"
            )

        results = []

        for prompt_data in data["prompts"]:
            prompt_name = prompt_data.get("name", "unknown")
            prompt_description = prompt_data.get("description", "")
            outcome: Dict[str, Any] = {"analyzers": [], "analyzer_errors": []}

            # Analyze prompt content. Title and other fields are included.
            # The strings are not fetched.
            analysis_content = f"Prompt Name: {prompt_name}\n"
            analysis_content += f"Description: {prompt_description}\n"

            if "arguments" in prompt_data:
                analysis_content += (
                    f"Arguments: {json.dumps(prompt_data['arguments'], indent=2)}\n"
                )
            extra = {
                key: value
                for key, value in prompt_data.items()
                if key not in {"name", "description", "arguments"}
                and value is not None
            }
            if extra:
                analysis_content += (
                    "Additional Fields:\n" + json.dumps(extra, indent=2) + "\n"
                )
            advertised_parts = []
            if "arguments" in prompt_data:
                advertised_parts.append(
                    "Arguments: "
                    + json.dumps(prompt_data["arguments"], indent=2)
                )
            if extra:
                advertised_parts.append(
                    "Additional Fields:\n" + json.dumps(extra, indent=2)
                )

            context = {"prompt_name": prompt_name, "content_type": "prompt"}

            findings = await self._analyze_content(
                analysis_content, context, outcome=outcome
            )

            result = {
                "prompt_name": prompt_name,
                "prompt_description": prompt_description,
                "advertised_text": "\n".join(advertised_parts),
                "findings": findings,
                **self._scan_outcome(findings, outcome),
            }

            results.append(result)

        return results

    async def scan_resources_file(
        self,
        file_path: Union[str, Path],
        allowed_mime_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan a JSON file containing MCP resources/list or resources/read output.

        Expected resources/list JSON format:
        {
          "resources": [
            {
              "uri": "file:///path/to/resource",
              "name": "Resource name",
              "description": "Resource description",
              "mimeType": "text/plain"
            }
          ]
        }

        Expected resources/read JSON format:
        {
          "contents": [
            {
              "uri": "file:///path/to/resource",
              "mimeType": "text/plain",
              "text": "Resource contents"
            }
          ]
        }

        Args:
            file_path: Path to the resources JSON file.
            allowed_mime_types: Optional list of MIME types to scan. Others are skipped.

        Returns:
            List[Dict]: List of scan results.

        Raises:
            FileNotFoundError: If file doesn't exist.
            json.JSONDecodeError: If file contains invalid JSON.
            ValueError: If JSON structure is invalid.
        """
        data = self._load_json_file(file_path)

        has_resources = "resources" in data
        has_contents = "contents" in data

        if not has_resources and not has_contents:
            raise ValueError(
                f"Invalid resources file: missing 'resources' or 'contents' key in {file_path}"
            )

        if has_resources and not isinstance(data["resources"], list):
            raise ValueError(
                f"Invalid resources file: 'resources' must be an array in {file_path}"
            )

        if has_contents and not isinstance(data["contents"], list):
            raise ValueError(
                f"Invalid resources file: 'contents' must be an array in {file_path}"
            )

        results = []
        contents_by_uri = self._group_resource_contents(data.get("contents", []))

        if has_resources:
            for resource_data in data["resources"]:
                resource_uri = resource_data.get("uri", "unknown")
                embedded_contents = resource_data.get("contents", [])
                content_items = (
                    list(embedded_contents)
                    if isinstance(embedded_contents, list)
                    else []
                )
                content_items.extend(contents_by_uri.pop(str(resource_uri), []))
                results.append(
                    await self._scan_resource_data(
                        resource_data,
                        allowed_mime_types=allowed_mime_types,
                        content_items=content_items,
                        skip_blob_only=False,
                    )
                )

        for content_items in contents_by_uri.values():
            if not content_items:
                continue
            results.append(
                await self._scan_resource_data(
                    content_items[0],
                    allowed_mime_types=allowed_mime_types,
                    content_items=content_items,
                    skip_blob_only=True,
                )
            )

        return results

    @staticmethod
    def _group_resource_contents(
        contents: List[Dict[str, Any]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for item in contents:
            if not isinstance(item, dict):
                continue
            uri = str(item.get("uri", "unknown"))
            grouped.setdefault(uri, []).append(item)
        return grouped

    @staticmethod
    def _resource_text_content(
        resource_data: Dict[str, Any],
        content_items: List[Dict[str, Any]],
    ) -> Tuple[str, bool]:
        text_parts = []
        saw_blob = bool(resource_data.get("blob"))

        for key in ("text", "content"):
            value = resource_data.get(key)
            if isinstance(value, str):
                text_parts.append(value)

        for item in content_items:
            if not isinstance(item, dict):
                continue
            if item is resource_data:
                continue
            for key in ("text", "content"):
                value = item.get(key)
                if isinstance(value, str):
                    text_parts.append(value)
            if item.get("blob"):
                saw_blob = True

        return "\n".join(text_parts), saw_blob

    @staticmethod
    def _resource_text_segments(
        resource_data: Dict[str, Any],
        content_items: List[Dict[str, Any]],
    ) -> List[tuple]:
        """Return ``(mime, text)`` for each text segment.

        A segment keeps the MIME type of the object it came from. A joined
        item does not relabel the list entry's own text. An item with no
        type inherits the list type. Blob bytes are not included.
        """
        list_mime = ""
        listed = resource_data.get("mimeType")
        if listed not in (None, "", [], {}):
            list_mime = str(listed)
        segments = []
        for key in ("text", "content"):
            value = resource_data.get(key)
            if isinstance(value, str) and value:
                segments.append((list_mime, value))
        for item in content_items:
            if not isinstance(item, dict) or item is resource_data:
                continue
            raw = item.get("mimeType")
            item_mime = list_mime if raw in (None, "", [], {}) else str(raw)
            for key in ("text", "content"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    segments.append((item_mime, value))
        return segments

    @staticmethod
    def _resource_advertised_text(
        resource_data: Dict[str, Any],
        content_items: List[Dict[str, Any]],
        resource_uri: str,
        resource_name: str,
        resource_description: str,
        resource_mime: str,
    ) -> str:
        """Render fields that are not the body.

        Fields on a joined read item are included. Blob bytes and body
        text are not. Nothing is fetched.
        """
        body_keys = {"text", "content", "blob", "contents"}
        extra = {}
        for key, value in resource_data.items():
            if key in body_keys or value is None:
                continue
            if key in {"uri", "name", "description"}:
                continue
            if key == "mimeType" and str(value) == resource_mime:
                continue
            extra[key] = value
        header = {
            "uri": resource_uri,
            "name": resource_name,
            "description": resource_description,
            "mimeType": resource_mime,
        }
        joined = []
        for item in content_items:
            if not isinstance(item, dict) or item is resource_data:
                continue
            fields = {}
            for key, value in item.items():
                if key in body_keys or value is None:
                    continue
                if key in header and value == header[key]:
                    continue
                fields[key] = value
            if fields:
                joined.append(fields)
        parts = []
        if extra:
            parts.append("Additional Fields:\n" + json.dumps(extra, indent=2))
        if joined:
            parts.append("Joined Content Fields:\n" + json.dumps(joined, indent=2))
        return "\n".join(parts)

    async def _skipped_body_result(
        self,
        resource_data: Dict[str, Any],
        resource_uri: str,
        resource_name: str,
        resource_description: str,
        resource_mime: str,
        advertised_text: str,
    ) -> Dict[str, Any]:
        """Skip an unscanned body without calling that resource safe.

        Title and other advertised fields are still scanned. They are not fetched.
        """
        result = {
            "resource_uri": resource_uri,
            "resource_name": resource_name,
            "resource_mime_type": resource_mime,
            "resource_description": resource_description,
            # The body was not scanned. Keeping it here would hand the
            # excluded text to meta-analysis.
            "resource_text": "",
            "is_safe": None,
            "findings": [],
            "status": "skipped",
            "analyzers": [],
            "advertised_text": advertised_text,
        }
        # The body stays out of this scan. Name and description are still
        # scanned, and a clean description does not make the body safe.
        analysis_content = (
            f"Resource URI: {resource_uri}\n"
            f"Name: {resource_name}\n"
            f"Description: {resource_description}\n"
            f"MIME Type: {resource_mime}\n"
        )
        if advertised_text:
            analysis_content += advertised_text + "\n"
        context = {
            "resource_uri": resource_uri,
            "resource_name": resource_name,
            "content_type": "resource",
            "has_resource_content": False,
        }
        outcome: Dict[str, Any] = {"analyzers": [], "analyzer_errors": []}
        findings = await self._analyze_content(
            analysis_content, context, outcome=outcome
        )
        if not findings and not outcome["analyzer_errors"]:
            return result
        result["findings"] = findings
        result.update(self._scan_outcome(findings, outcome))
        return result

    async def _scan_resource_data(
        self,
        resource_data: Dict[str, Any],
        allowed_mime_types: Optional[List[str]],
        content_items: Optional[List[Dict[str, Any]]] = None,
        skip_blob_only: bool = False,
    ) -> Dict[str, Any]:
        content_items = content_items or []
        first_content = content_items[0] if content_items else {}

        if not isinstance(resource_data, dict):
            resource_data = {}

        resource_uri = resource_data.get("uri") or first_content.get("uri") or "unknown"
        resource_uri = str(resource_uri)
        resource_name = (
            resource_data.get("name") or first_content.get("name") or resource_uri
        )
        resource_description = resource_data.get("description", "")
        if resource_description in (None, "", [], {}):
            for item in content_items:
                if not isinstance(item, dict) or item is resource_data:
                    continue
                candidate = item.get("description")
                if candidate in (None, "", [], {}):
                    continue
                resource_description = (
                    candidate
                    if isinstance(candidate, str)
                    else json.dumps(candidate)
                )
                break
        _raw_text, saw_blob = self._resource_text_content(
            resource_data, content_items
        )
        segments = self._resource_text_segments(resource_data, content_items)
        allowed = None
        if allowed_mime_types:
            allowed = {_normalize_mime_type(mime) for mime in allowed_mime_types}
        included_parts = []
        included_mimes: List[str] = []
        for segment_mime, segment_text in segments:
            chosen = segment_mime or "text/plain"
            normalized = _normalize_mime_type(chosen) or "text/plain"
            if allowed is not None and normalized not in allowed:
                continue
            extracted = _extract_html_text_if_needed(segment_text, chosen)
            if extracted:
                included_parts.append(extracted)
                included_mimes.append(chosen)
        text_content = "\n".join(included_parts)
        if included_mimes:
            resource_mime = included_mimes[0]
        else:
            listed = resource_data.get("mimeType")
            if listed not in (None, "", [], {}):
                resource_mime = str(listed)
            elif segments:
                resource_mime = segments[0][0] or "application/octet-stream"
            else:
                resource_mime = (
                    "text/plain" if _raw_text else "application/octet-stream"
                )
        advertised_text = self._resource_advertised_text(
            resource_data,
            content_items,
            resource_uri,
            resource_name,
            resource_description if isinstance(resource_description, str) else "",
            resource_mime,
        )
        # Every text segment belonged to a filtered MIME type. Skipping
        # the body must not mark that unread text safe.
        if not included_parts and segments and allowed is not None:
            return await self._skipped_body_result(
                resource_data,
                resource_uri,
                resource_name,
                resource_description,
                resource_mime,
                advertised_text,
            )

        if skip_blob_only and saw_blob and not text_content:
            return await self._skipped_body_result(
                resource_data,
                resource_uri,
                resource_name,
                resource_description,
                resource_mime,
                advertised_text,
            )

        # A disallowed MIME type skips the body. Advertised fields are
        # still scanned, and the skip is not reported as safe.
        if allowed_mime_types and _normalize_mime_type(resource_mime) not in {
            _normalize_mime_type(m) for m in allowed_mime_types
        }:
            return await self._skipped_body_result(
                resource_data,
                resource_uri,
                resource_name,
                resource_description,
                resource_mime,
                advertised_text,
            )

        # Analyze resource metadata and text content when present.
        analysis_content = f"Resource URI: {resource_uri}\n"
        analysis_content += f"Name: {resource_name}\n"
        analysis_content += f"Description: {resource_description}\n"
        analysis_content += f"MIME Type: {resource_mime}\n"
        if advertised_text:
            # Title, annotations, and joined read-item fields are not fetched.
            analysis_content += advertised_text + "\n"
        if text_content:
            analysis_content += f"Content:\n{text_content}\n"

        context = {
            "resource_uri": resource_uri,
            "resource_name": resource_name,
            "content_type": "resource",
            "has_resource_content": bool(text_content),
        }

        outcome: Dict[str, Any] = {"analyzers": [], "analyzer_errors": []}
        findings = await self._analyze_content(
            analysis_content, context, outcome=outcome
        )

        return {
            "resource_uri": resource_uri,
            "resource_name": resource_name,
            "resource_mime_type": resource_mime,
            # P0-3 plumbing for the static path. The remote ``_analyze_resource``
            # already persists these on the resulting ``ResourceScanResult``;
            # without these dict keys the CLI couldn't wire them through and
            # ``--enable-meta`` would feed the meta-analyzer ``"N/A"`` for
            # description (sees only name + uri + mime_type), making FP
            # filtering on file-based resource scans unsupervised.
            #
            # Canonical shape (matches the remote path and the skip
            # branches above): ``resource_description`` is the
            # MCP-advertised description verbatim, and ``resource_text``
            # is the resource BODY only — never the LLM-formatted
            # ``analysis_content`` blob (which prepends ``Resource URI:``,
            # ``Name:``, ``Description:``, ``MIME Type:`` headers and
            # would duplicate the description into the body when the
            # meta-analyzer concats them via
            # ``Scanner._build_resource_description_for_meta``).
            "resource_description": resource_description,
            "resource_text": text_content,
            "advertised_text": advertised_text,
            "findings": findings,
            **self._scan_outcome(findings, outcome),
        }
