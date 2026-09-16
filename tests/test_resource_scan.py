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

"""Tests for the resource-scanning helpers shared by the two scan entry points."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.resource_scan import (
    extract_resource_text,
    mime_type_allowed,
    resource_placeholder,
)


def make_resource(uri="file:///a.txt", name="a", mime="text/plain"):
    return SimpleNamespace(uri=uri, name=name, mimeType=mime, description="")


class TestResourcePlaceholder:
    def test_carries_identity_and_status_but_no_findings(self):
        result = resource_placeholder(make_resource(), "skipped")

        assert result.resource_uri == "file:///a.txt"
        assert result.resource_name == "a"
        assert result.resource_mime_type == "text/plain"
        assert result.status == "skipped"
        assert result.findings == []
        assert result.analyzers == []

    def test_absent_name_and_mime_get_defaults(self):
        result = resource_placeholder(make_resource(name=None, mime=None), "failed")

        assert result.resource_name == ""
        assert result.resource_mime_type == "unknown"


class TestMimeTypeAllowed:
    def test_listed_type_is_allowed(self):
        assert mime_type_allowed(make_resource(mime="text/plain"), ["text/plain"])

    def test_unlisted_type_is_rejected(self):
        assert not mime_type_allowed(make_resource(mime="image/png"), ["text/plain"])

    def test_unspecified_type_is_allowed(self):
        # A server that says nothing about MIME type has not said "binary".
        assert mime_type_allowed(make_resource(mime=None), ["text/plain"])


class TestExtractResourceText:
    def test_concatenates_text_parts(self):
        contents = SimpleNamespace(
            contents=[SimpleNamespace(text="one "), SimpleNamespace(text="two")]
        )

        assert extract_resource_text(contents, "u") == "one two"

    def test_skips_blob_parts(self):
        blob = SimpleNamespace(blob=b"\x00")
        contents = SimpleNamespace(contents=[SimpleNamespace(text="keep"), blob])

        assert extract_resource_text(contents, "u") == "keep"

    def test_malformed_payload_is_distinguishable_from_empty_text(self):
        # None means "could not read"; "" means "read fine, no text in it".
        assert extract_resource_text(SimpleNamespace(contents=None), "u") is None
        assert extract_resource_text(SimpleNamespace(contents=[]), "u") == ""


class TestReadAndAnalyzeErrorHandling:
    """The two callers differ in whether an analysis error aborts the scan."""

    @pytest.fixture
    def scanner(self):
        return Scanner(Config(api_key="k"))

    @pytest.fixture
    def session(self):
        return SimpleNamespace(
            read_resource=AsyncMock(
                return_value=SimpleNamespace(contents=[SimpleNamespace(text="body")])
            )
        )

    @pytest.mark.asyncio
    async def test_bulk_scan_absorbs_analysis_error(self, scanner, session, monkeypatch):
        monkeypatch.setattr(
            scanner, "_analyze_resource", AsyncMock(side_effect=RuntimeError("boom"))
        )

        result = await scanner._read_and_analyze_resource(
            session,
            make_resource(),
            [AnalyzerEnum.API],
            None,
            absorb_analysis_errors=True,
        )

        assert result.status == "failed"

    @pytest.mark.asyncio
    async def test_single_scan_propagates_analysis_error(
        self, scanner, session, monkeypatch
    ):
        monkeypatch.setattr(
            scanner, "_analyze_resource", AsyncMock(side_effect=RuntimeError("boom"))
        )

        with pytest.raises(RuntimeError):
            await scanner._read_and_analyze_resource(
                session,
                make_resource(),
                [AnalyzerEnum.API],
                None,
                absorb_analysis_errors=False,
            )

    @pytest.mark.asyncio
    async def test_read_failure_is_a_placeholder_for_both_callers(self, scanner):
        session = SimpleNamespace(
            read_resource=AsyncMock(side_effect=RuntimeError("unreachable"))
        )

        for absorb in (True, False):
            result = await scanner._read_and_analyze_resource(
                session,
                make_resource(),
                [AnalyzerEnum.API],
                None,
                absorb_analysis_errors=absorb,
            )
            assert result.status == "failed"
