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

"""Shared JSON parsing utilities for LLM responses.

LLMs often wrap JSON output in markdown code fences (```json ... ```).
This module provides a parser that handles both plain JSON and
markdown-wrapped JSON transparently.
"""

import json
from typing import Any, Dict, Optional


def parse_json_from_llm(response: str) -> Optional[Dict[str, Any]]:
    """Parse a JSON object from an LLM response, handling markdown code fences.

    Attempts plain JSON parsing first, then falls back to extracting JSON
    from markdown code blocks (```json ... ``` or ``` ... ```).

    Args:
        response: Raw LLM response text.

    Returns:
        Parsed dict, or None if parsing fails.
    """
    # Try plain JSON first
    try:
        data = json.loads(response)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass

    # Fall back to extracting from markdown code fences
    return _extract_json_from_markdown(response)


def _extract_json_from_markdown(response: str) -> Optional[Dict[str, Any]]:
    """Extract a JSON object from markdown code blocks."""
    try:
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            json_str = response[start:end].strip()
        elif "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            json_str = response[start:end].strip()
        else:
            return None

        data = json.loads(json_str)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass

    return None
