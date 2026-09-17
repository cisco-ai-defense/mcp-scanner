# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Tests for the OPA readiness provider.

OPA is optional and usually absent, which is why so little of this ran
before: every path short-circuits at is_available(). The binary is
stubbed here so the parts that matter can be exercised -- the facts
document policies are written against, the parsing of OPA's output, and
the severity a violation ends up carrying.
"""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from mcpscanner.core.analyzers.readiness.opa_provider import (
    POLICY_CATEGORY_MAP,
    OpaProvider,
)


def facts_for(definition, name="my_tool"):
    return OpaProvider()._create_tool_facts(definition, name)


def fake_opa(stdout=b"", stderr=b"", returncode=0):
    """Stand in for an OPA subprocess returning a canned result."""
    process = AsyncMock()
    process.communicate = AsyncMock(return_value=(stdout, stderr))
    process.returncode = returncode
    return patch("asyncio.create_subprocess_exec", AsyncMock(return_value=process))


def opa_output(*messages):
    return json.dumps({"result": [{"value": list(messages)}]}).encode()


@pytest.fixture
def policies(tmp_path):
    """A policies directory holding one (never actually run) policy file."""
    d = tmp_path / "policies"
    d.mkdir()
    (d / "timeout.rego").write_text("package mcp.readiness\n")
    return d


@pytest.fixture
def provider(policies):
    """A provider that believes OPA is installed."""
    p = OpaProvider(policies_dir=policies)
    p._opa_path = "/usr/local/bin/opa"
    p._availability_checked = True
    return p


class TestAvailability:
    def test_name_is_stable(self):
        assert OpaProvider().name == "opa"

    def test_missing_binary_is_unavailable(self):
        with patch("shutil.which", return_value=None):
            assert OpaProvider().is_available() is False

    def test_present_binary_is_available(self):
        with patch("shutil.which", return_value="/usr/local/bin/opa"):
            assert OpaProvider().is_available() is True

    def test_lookup_happens_only_once(self):
        with patch("shutil.which", return_value="/bin/opa") as which:
            p = OpaProvider()
            p.is_available()
            p.is_available()
            assert which.call_count == 1

    def test_unavailable_reason_names_the_binary(self):
        with patch("shutil.which", return_value=None):
            reason = OpaProvider(opa_binary="opa-custom").get_unavailable_reason()
        assert "opa-custom" in reason

    def test_available_provider_has_no_reason(self):
        with patch("shutil.which", return_value="/bin/opa"):
            assert OpaProvider().get_unavailable_reason() is None

    @pytest.mark.asyncio
    async def test_evaluation_is_skipped_when_opa_is_missing(self):
        with patch("shutil.which", return_value=None):
            assert await OpaProvider().evaluate_tool({}, "t") == []


class TestToolFacts:
    def test_tool_name_and_type_are_recorded(self):
        f = facts_for({}, "lookup_user")
        assert f["type"] == "tool"
        assert f["tool_name"] == "lookup_user"

    @pytest.mark.parametrize(
        "field", ["timeout", "timeoutMs", "timeout_ms", "timeoutSeconds"]
    )
    def test_each_timeout_spelling_is_recognised(self, field):
        f = facts_for({field: 30})
        assert f["has_timeout"] is True
        assert f["timeout_value"] == 30

    def test_timeout_nested_under_config_is_recognised(self):
        f = facts_for({"config": {"timeout": 15}})
        assert f["has_timeout"] is True
        assert f["timeout_value"] == 15

    def test_absent_timeout_is_reported_as_absent(self):
        f = facts_for({})
        assert f["has_timeout"] is False
        assert f["timeout_value"] is None

    @pytest.mark.parametrize(
        "field", ["retries", "maxRetries", "max_retries", "retryLimit", "retry_limit"]
    )
    def test_each_retry_spelling_is_recognised(self, field):
        f = facts_for({field: 3})
        assert f["has_retry_limit"] is True
        assert f["retry_limit"] == 3

    def test_retry_nested_under_config_is_recognised(self):
        assert facts_for({"config": {"maxRetries": 5}})["retry_limit"] == 5

    def test_capabilities_are_counted(self):
        assert facts_for({"capabilities": ["a", "b", "c"]})["capabilities_count"] == 3

    def test_non_list_capabilities_count_as_zero(self):
        assert facts_for({"capabilities": "read"})["capabilities_count"] == 0

    @pytest.mark.parametrize(
        "field", ["errorSchema", "error_schema", "errors", "errorResponse"]
    )
    def test_each_error_schema_spelling_is_recognised(self, field):
        assert facts_for({field: {}})["has_error_schema"] is True

    def test_input_schema_shape_is_summarised(self):
        f = facts_for(
            {
                "inputSchema": {
                    "properties": {"a": {}, "b": {}},
                    "required": ["a"],
                }
            }
        )
        assert f["has_input_schema"] is True
        assert f["input_properties_count"] == 2
        assert f["has_required_fields"] is True

    def test_missing_input_schema_is_reported_as_absent(self):
        f = facts_for({})
        assert f["has_input_schema"] is False
        assert f["input_properties_count"] == 0
        assert f["has_required_fields"] is False

    def test_description_length_is_measured(self):
        f = facts_for({"description": "Looks up a user."})
        assert f["has_description"] is True
        assert f["description_length"] == len("Looks up a user.")

    def test_empty_description_is_reported_as_absent(self):
        f = facts_for({"description": ""})
        assert f["has_description"] is False
        assert f["description_length"] == 0

    @pytest.mark.parametrize(
        "field", ["rateLimit", "rate_limit", "throttle", "rateLimitPerMinute"]
    )
    def test_each_rate_limit_spelling_is_recognised(self, field):
        assert facts_for({field: 100})["has_rate_limit"] is True

    def test_raw_definition_is_carried_through_for_advanced_policies(self):
        definition = {"custom": {"nested": True}}
        assert facts_for(definition)["raw"] == definition

    def test_facts_are_json_serialisable(self):
        """They are written to a temp file for OPA, so they must serialise."""
        json.dumps(facts_for({"timeout": 5, "capabilities": ["x"]}))


class TestEnrichment:
    def enrich(self, **violation):
        return OpaProvider()._enrich_violation(violation)

    @pytest.mark.parametrize("key,category", sorted(POLICY_CATEGORY_MAP.items()))
    def test_policy_name_selects_its_category(self, key, category):
        assert self.enrich(policy=key, message="m")["category"] == category

    def test_unmapped_policy_falls_back_to_a_default_category(self):
        assert self.enrich(policy="mystery", message="m")["category"] == (
            "SILENT_FAILURE_PATH"
        )

    def test_category_match_is_case_insensitive(self):
        assert self.enrich(policy="TIMEOUT", message="m")["category"] == (
            "MISSING_TIMEOUT_GUARD"
        )

    @pytest.mark.parametrize(
        "message,severity",
        [
            ("Tool must declare a timeout", "HIGH"),
            ("A timeout is required", "HIGH"),
            ("Tool should declare a timeout", "MEDIUM"),
            ("A timeout is recommended", "MEDIUM"),
            ("You may add a timeout", "LOW"),
            ("Consider adding a timeout", "LOW"),
            ("Timeout absent", "MEDIUM"),
        ],
    )
    def test_wording_drives_severity(self, message, severity):
        assert self.enrich(policy="timeout", message=message)["severity"] == severity

    def test_error_violations_are_informational(self):
        out = self.enrich(policy="timeout", message="timed out", is_error=True)
        assert out["severity"] == "INFO"

    def test_rule_id_is_derived_from_the_policy(self):
        assert self.enrich(policy="timeout", message="m")["rule_id"] == "OPA-timeout"

    def test_missing_fields_get_defaults(self):
        out = self.enrich()
        assert out["message"] == "Policy violation"
        assert out["policy"] == "unknown"


class TestPolicyEvaluation:
    @pytest.mark.asyncio
    async def test_missing_policies_directory_yields_nothing(self, tmp_path):
        p = OpaProvider(policies_dir=tmp_path / "absent")
        p._opa_path, p._availability_checked = "/bin/opa", True
        assert await p.evaluate_tool({}, "t") == []

    @pytest.mark.asyncio
    async def test_directory_without_policies_yields_nothing(self, tmp_path):
        (tmp_path / "policies").mkdir()
        p = OpaProvider(policies_dir=tmp_path / "policies")
        p._opa_path, p._availability_checked = "/bin/opa", True
        assert await p.evaluate_tool({}, "t") == []

    @pytest.mark.asyncio
    async def test_violations_are_returned_and_enriched(self, provider):
        with fake_opa(stdout=opa_output("Tool must declare a timeout")):
            out = await provider.evaluate_tool({}, "my_tool")
        assert len(out) == 1
        assert out[0]["category"] == "MISSING_TIMEOUT_GUARD"
        assert out[0]["severity"] == "HIGH"
        assert out[0]["policy"] == "timeout"

    @pytest.mark.asyncio
    async def test_several_messages_become_several_violations(self, provider):
        with fake_opa(stdout=opa_output("first must fix", "second should fix")):
            out = await provider.evaluate_tool({}, "my_tool")
        assert [v["severity"] for v in out] == ["HIGH", "MEDIUM"]

    @pytest.mark.asyncio
    async def test_a_bare_string_result_is_accepted(self, provider):
        payload = json.dumps({"result": [{"value": "must fix"}]}).encode()
        with fake_opa(stdout=payload):
            assert len(await provider.evaluate_tool({}, "t")) == 1

    @pytest.mark.asyncio
    async def test_non_string_messages_are_stringified(self, provider):
        payload = json.dumps({"result": [{"value": [{"detail": 1}]}]}).encode()
        with fake_opa(stdout=payload):
            out = await provider.evaluate_tool({}, "t")
        assert isinstance(out[0]["message"], str)

    @pytest.mark.asyncio
    async def test_an_empty_result_yields_nothing(self, provider):
        with fake_opa(stdout=json.dumps({"result": []}).encode()):
            assert await provider.evaluate_tool({}, "t") == []

    @pytest.mark.asyncio
    async def test_a_failing_opa_run_yields_nothing(self, provider):
        with fake_opa(stdout=b"", stderr=b"rego parse error", returncode=1):
            assert await provider.evaluate_tool({}, "t") == []

    @pytest.mark.asyncio
    async def test_unparseable_output_yields_nothing(self, provider):
        with fake_opa(stdout=b"not json at all"):
            assert await provider.evaluate_tool({}, "t") == []

    @pytest.mark.asyncio
    async def test_a_timeout_is_surfaced_as_an_informational_violation(self, provider):
        process = AsyncMock()
        process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=process)):
            out = await provider.evaluate_tool({}, "t")
        assert len(out) == 1
        assert out[0]["severity"] == "INFO"
        assert "timed out" in out[0]["message"]

    @pytest.mark.asyncio
    async def test_a_crash_launching_opa_yields_nothing(self, provider):
        with patch(
            "asyncio.create_subprocess_exec", AsyncMock(side_effect=OSError("no exec"))
        ):
            assert await provider.evaluate_tool({}, "t") == []

    @pytest.mark.asyncio
    async def test_the_input_temp_file_is_removed_afterwards(self, provider):
        seen = {}
        real = json.dump

        def capture(obj, fh, *a, **kw):
            seen["path"] = fh.name
            return real(obj, fh, *a, **kw)

        with patch("json.dump", side_effect=capture):
            with fake_opa(stdout=opa_output("must fix")):
                await provider.evaluate_tool({}, "t")

        from pathlib import Path

        assert not Path(seen["path"]).exists()

    @pytest.mark.asyncio
    async def test_the_facts_document_is_what_opa_is_given(self, provider):
        with fake_opa(stdout=opa_output()) as spawn:
            await provider.evaluate_tool({"timeout": 9}, "named_tool")
        argv = spawn.call_args[0]
        assert "eval" in argv
        assert "data.mcp.readiness.violation" in argv
