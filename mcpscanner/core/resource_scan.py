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

"""Shared pieces of MCP resource scanning.

A resource can drop out of a scan for six different reasons -- wrong MIME
type, binary content, unreadable content, a read timeout, a read error, an
analysis error -- and each one produced its own hand-written
``ResourceScanResult`` with empty findings. Scanning one resource and scanning
all of them each carried a full set, so the same six-field constructor
appeared eleven times across two methods.
"""

from typing import Any, List, Optional

from ..utils.logging_config import get_logger
from .result import ResourceScanResult

logger = get_logger(__name__)

# MIME types whose contents are worth handing to a text analyzer.
DEFAULT_ALLOWED_MIME_TYPES = ["text/plain", "text/html"]


def resource_placeholder(resource: Any, status: str) -> ResourceScanResult:
    """A findings-free result for a resource the scan did not analyze.

    ``status`` distinguishes a deliberate skip from a failure; both carry no
    findings, so neither makes the server look unsafe.
    """
    return ResourceScanResult(
        resource_uri=resource.uri,
        resource_name=resource.name or "",
        resource_mime_type=resource.mimeType or "unknown",
        status=status,
        analyzers=[],
        findings=[],
    )


def mime_type_allowed(resource: Any, allowed: List[str]) -> bool:
    """Whether the resource's MIME type is one the scan will read.

    A resource that advertises no MIME type is allowed through: the server
    simply didn't say, which is not the same as saying something unsupported.
    """
    return not resource.mimeType or resource.mimeType in allowed


def extract_resource_text(contents: Any, uri: Any) -> Optional[str]:
    """Concatenate the text parts of a resource read, skipping binary parts.

    Returns ``None`` when the payload is not shaped the way the MCP spec says
    it should be -- distinct from ``""``, which means the resource was read
    correctly and simply holds no text.
    """
    text = ""
    try:
        for content in contents.contents:
            if hasattr(content, "text"):
                text += content.text
            elif hasattr(content, "blob"):
                logger.info("Skipping binary content for resource '%s'", uri)
    except (AttributeError, TypeError) as e:
        logger.warning("Error extracting content from resource '%s': %s", uri, e)
        return None
    return text
