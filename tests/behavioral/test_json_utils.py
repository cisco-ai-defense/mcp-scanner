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

"""Tests for JSON parsing utilities used by alignment components."""

import json

import pytest

from mcpscanner.core.analyzers.behavioral.alignment.json_utils import (
    parse_json_from_llm,
)


class TestParseJsonFromLlm:
    """Tests for parse_json_from_llm."""

    def test_plain_json(self):
        payload = {"mismatch_detected": True, "summary": "found something"}
        result = parse_json_from_llm(json.dumps(payload))
        assert result == payload

    def test_json_fenced_block(self):
        payload = {"classification": "THREAT", "confidence": "HIGH"}
        raw = f"```json\n{json.dumps(payload, indent=2)}\n```"
        result = parse_json_from_llm(raw)
        assert result == payload

    def test_bare_fenced_block(self):
        payload = {"classification": "VULNERABILITY", "confidence": "LOW"}
        raw = f"```\n{json.dumps(payload)}\n```"
        result = parse_json_from_llm(raw)
        assert result == payload

    def test_fenced_block_with_surrounding_text(self):
        payload = {"key": "value"}
        raw = f"Here is the result:\n```json\n{json.dumps(payload)}\n```\nDone."
        result = parse_json_from_llm(raw)
        assert result == payload

    def test_returns_none_for_non_dict_json(self):
        assert parse_json_from_llm("[1, 2, 3]") is None

    def test_returns_none_for_garbage(self):
        assert parse_json_from_llm("this is not json at all") is None

    def test_returns_none_for_empty_string(self):
        assert parse_json_from_llm("") is None

    def test_returns_none_for_invalid_json_in_fence(self):
        assert parse_json_from_llm("```json\n{bad json\n```") is None

    def test_returns_none_for_non_dict_in_fence(self):
        assert parse_json_from_llm('```json\n["a","b"]\n```') is None
