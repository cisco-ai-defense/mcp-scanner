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
from ..models import AnalyzerEnum
from ...utils.logging_config import get_logger

logger = get_logger(__name__)


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
    if mime_type != "text/html" or not content:
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
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Run all configured analyzers on the content.

        Args:
            content: Content to analyze.
            context: Additional context for analysis.

        Returns:
            List[SecurityFinding]: Combined findings from all analyzers.
        """
        all_findings = []

        for analyzer in self.analyzers:
            try:
                findings = await analyzer.analyze(content, context)
                all_findings.extend(findings)
            except Exception as e:
                # Log error but continue with other analyzers
                print(f"Warning: {analyzer.name} failed: {e}")

        return all_findings

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

            all_findings = []

            # Analyze description
            if tool_description:
                desc_context = {"tool_name": tool_name, "content_type": "description"}
                desc_findings = await self._analyze_content(
                    tool_description, desc_context
                )
                all_findings.extend(desc_findings)

            # Analyze parameters (if present)
            if "inputSchema" in tool_data:
                # Remove description to avoid duplicate analysis
                params_data = {k: v for k, v in tool_data.items() if k != "description"}
                params_json = json.dumps(params_data)

                params_context = {"tool_name": tool_name, "content_type": "parameters"}
                params_findings = await self._analyze_content(
                    params_json, params_context
                )
                all_findings.extend(params_findings)

            result = {
                "tool_name": tool_name,
                "tool_description": tool_description,
                "is_safe": len(all_findings) == 0,
                "findings": all_findings,
                "status": "completed",
                "analyzers": [self._get_finding_analyzer_name(a) for a in self.analyzers],
            }

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

            # Analyze prompt content
            analysis_content = f"Prompt Name: {prompt_name}\n"
            analysis_content += f"Description: {prompt_description}\n"

            if "arguments" in prompt_data:
                analysis_content += (
                    f"Arguments: {json.dumps(prompt_data['arguments'], indent=2)}\n"
                )

            context = {"prompt_name": prompt_name, "content_type": "prompt"}

            findings = await self._analyze_content(analysis_content, context)

            result = {
                "prompt_name": prompt_name,
                "prompt_description": prompt_description,
                "is_safe": len(findings) == 0,
                "findings": findings,
                "status": "completed",
                "analyzers": [self._get_finding_analyzer_name(a) for a in self.analyzers],
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
            text = item.get("text")
            if isinstance(text, str):
                text_parts.append(text)
            if item.get("blob"):
                saw_blob = True

        return "\n".join(text_parts), saw_blob

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
        text_content, saw_blob = self._resource_text_content(
            resource_data, content_items
        )
        resource_mime = resource_data.get("mimeType") or first_content.get("mimeType")
        if not resource_mime:
            resource_mime = "text/plain" if text_content else "application/octet-stream"

        # H5 fix: strip HTML on the static path so ``resource_text``
        # produced here byte-matches what ``Scanner._analyze_resource``
        # produces on the remote path. Without this, a ``text/html``
        # resource scanned from a JSON file shipped raw markup to the
        # meta-analyzer while the same resource scanned via
        # ``scan-remote-server`` shipped extracted text — divergent
        # prompts → divergent FP-filter decisions for the same content.
        text_content = _extract_html_text_if_needed(text_content, resource_mime)

        if skip_blob_only and saw_blob and not text_content:
            return {
                "resource_uri": resource_uri,
                "resource_name": resource_name,
                "resource_mime_type": resource_mime,
                # Surface the MCP-advertised description and the text we
                # would have analysed even on the skip path; downstream
                # ``ResourceScanResult`` construction can persist them
                # verbatim, and the meta-analyzer can second-guess
                # follow-up reads of the same resource against the same
                # evidence the primary pass saw.
                "resource_description": resource_description,
                "resource_text": text_content,
                "is_safe": True,
                "findings": [],
                "status": "skipped",
                "analyzers": [],
            }

        # Check MIME type filter — resource isn't scanned, return a "skipped"
        # result that matches the shape used by the skip_blob_only branch above.
        # Bug fix: previously this branch referenced an undefined `findings`
        # variable, since `findings` is only assigned by the analysis path below.
        if allowed_mime_types and resource_mime not in allowed_mime_types:
            return {
                "resource_uri": resource_uri,
                "resource_name": resource_name,
                "resource_mime_type": resource_mime,
                "resource_description": resource_description,
                "resource_text": text_content,
                "is_safe": True,
                "findings": [],
                "status": "skipped",
                "analyzers": [],
            }

        # Analyze resource metadata and text content when present.
        analysis_content = f"Resource URI: {resource_uri}\n"
        analysis_content += f"Name: {resource_name}\n"
        analysis_content += f"Description: {resource_description}\n"
        analysis_content += f"MIME Type: {resource_mime}\n"
        if text_content:
            analysis_content += f"Content:\n{text_content}\n"

        context = {
            "resource_uri": resource_uri,
            "resource_name": resource_name,
            "content_type": "resource",
            "has_resource_content": bool(text_content),
        }

        findings = await self._analyze_content(analysis_content, context)

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
            "is_safe": len(findings) == 0,
            "findings": findings,
            "status": "completed",
            "analyzers": [a.name for a in self.analyzers],
        }
