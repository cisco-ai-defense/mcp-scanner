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

"""Tests for policy modules: network, filesystem, and data classifier."""

import json
import tempfile
from pathlib import Path

import pytest

from mcpscanner.core.policy.network_policy import NetworkPolicy, NetworkPolicyViolation
from mcpscanner.core.policy.filesystem_policy import (
    FilesystemPolicy,
    FilesystemPolicyViolation,
)
from mcpscanner.core.policy.data_classifier import DataClassifier, DataClassification


# ── NetworkPolicy ──


class TestNetworkPolicy:
    def _write_policy(self, data: dict) -> str:
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(data, f)
        f.close()
        return f.name

    def test_no_config_no_violations(self):
        policy = NetworkPolicy()
        assert not policy.is_configured
        violations = policy.check_strings(["https://evil.com/steal"])
        assert violations == []

    def test_deny_mode_blocks_denied_domain(self):
        path = self._write_policy(
            {"mode": "deny", "deny_domains": ["evil.com", "*.attacker.io"]}
        )
        policy = NetworkPolicy(config_path=path)
        assert policy.is_configured

        violations = policy.check_strings(
            ["https://evil.com/exfil", "https://safe.org/ok"]
        )
        assert len(violations) == 1
        assert violations[0].destination == "evil.com"

    def test_deny_mode_wildcard_match(self):
        path = self._write_policy(
            {"mode": "deny", "deny_domains": ["*.attacker.io"]}
        )
        policy = NetworkPolicy(config_path=path)
        violations = policy.check_strings(["https://c2.attacker.io/beacon"])
        assert len(violations) == 1

    def test_allow_mode_blocks_unlisted(self):
        path = self._write_policy(
            {"mode": "allow", "allow_domains": ["api.github.com"]}
        )
        policy = NetworkPolicy(config_path=path)
        violations = policy.check_strings(
            ["https://api.github.com/repos", "https://random.com/api"]
        )
        assert len(violations) == 1
        assert violations[0].destination == "random.com"

    def test_deny_ip(self):
        path = self._write_policy(
            {"mode": "deny", "deny_ips": ["198.51.100.0/24"]}
        )
        policy = NetworkPolicy(config_path=path)
        violations = policy.check_strings(["http://198.51.100.5/exfil"])
        assert len(violations) == 1

    def test_allow_private_ips(self):
        path = self._write_policy(
            {"mode": "allow", "allow_ips": ["10.0.0.0/8", "192.168.0.0/16"]}
        )
        policy = NetworkPolicy(config_path=path)
        violations = policy.check_strings(["http://8.8.8.8/dns"])
        assert len(violations) == 1
        assert violations[0].destination == "8.8.8.8"

    def test_bad_config_path(self):
        policy = NetworkPolicy(config_path="/nonexistent/policy.json")
        assert not policy.is_configured

    def test_deduplication(self):
        path = self._write_policy(
            {"mode": "deny", "deny_domains": ["evil.com"]}
        )
        policy = NetworkPolicy(config_path=path)
        violations = policy.check_strings(
            ["https://evil.com/a", "https://evil.com/b"]
        )
        assert len(violations) == 1  # same host, only one violation


# ── FilesystemPolicy ──


class TestFilesystemPolicy:
    def _write_policy(self, data: dict) -> str:
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(data, f)
        f.close()
        return f.name

    def test_no_config_no_violations(self):
        policy = FilesystemPolicy()
        assert not policy.is_configured
        violations = policy.check_strings(["/etc/shadow"])
        assert violations == []

    def test_traversal_detection(self):
        path = self._write_policy({"deny_traversal": True, "denied_paths": []})
        policy = FilesystemPolicy(config_path=path)
        # Traversal detection is always on by default even without policy config
        # but we need is_configured to be True
        # Actually, traversal runs even without is_configured being True
        # Let me test with allowed_directories to make is_configured True
        path = self._write_policy(
            {"allowed_directories": ["/tmp"], "deny_traversal": True}
        )
        policy = FilesystemPolicy(config_path=path)
        violations = policy.check_strings(["../../etc/passwd"])
        assert len(violations) >= 1
        assert any("traversal" in v.reason.lower() for v in violations)

    def test_denied_paths(self):
        path = self._write_policy(
            {"denied_paths": ["/etc/shadow", "~/.ssh"], "allowed_directories": []}
        )
        policy = FilesystemPolicy(config_path=path)
        violations = policy.check_strings(["/etc/shadow"])
        assert len(violations) >= 1
        assert any("/etc/shadow" in v.path for v in violations)

    def test_allowed_directories(self):
        path = self._write_policy(
            {"allowed_directories": ["/tmp", "/data"], "denied_paths": []}
        )
        policy = FilesystemPolicy(config_path=path)
        # /tmp/file.txt should be ok
        violations_ok = policy.check_strings(["/tmp/file.txt"])
        outside_violations = [
            v for v in violations_ok if "outside allowed" in v.reason.lower()
        ]
        assert len(outside_violations) == 0

        # /etc/config should be blocked
        violations = policy.check_strings(["/etc/config"])
        assert any("outside allowed" in v.reason.lower() for v in violations)

    def test_bad_config_path(self):
        policy = FilesystemPolicy(config_path="/nonexistent.json")
        assert not policy.is_configured


# ── DataClassifier ──


class TestDataClassifier:
    def test_no_sensitive_data(self):
        dc = DataClassifier()
        result = dc.classify_from_context(
            string_literals=["hello", "world"],
            env_var_access=[],
            parameter_names=["x", "y"],
            variable_names=["result"],
        )
        assert not result.has_sensitive_data
        assert result.categories == set()

    def test_detects_credentials(self):
        dc = DataClassifier()
        result = dc.classify_from_context(
            string_literals=[],
            env_var_access=["os.getenv('API_KEY')"],
            parameter_names=["password"],
            variable_names=["secret_token"],
        )
        assert result.has_sensitive_data
        assert "CREDENTIALS" in result.categories

    def test_detects_pii(self):
        dc = DataClassifier()
        result = dc.classify_from_context(
            string_literals=[],
            env_var_access=[],
            parameter_names=["ssn", "email_address"],
            variable_names=["full_name"],
        )
        assert "PII" in result.categories

    def test_detects_financial(self):
        dc = DataClassifier()
        result = dc.classify_from_context(
            string_literals=["credit_card_number"],
            env_var_access=[],
            parameter_names=[],
            variable_names=["bank_account"],
        )
        assert "FINANCIAL" in result.categories

    def test_detects_system_data(self):
        dc = DataClassifier()
        result = dc.classify_from_context(
            string_literals=["/etc/shadow", ".ssh/authorized_keys"],
            env_var_access=[],
            parameter_names=[],
            variable_names=[],
        )
        assert "SYSTEM_DATA" in result.categories

    def test_detects_ip(self):
        dc = DataClassifier()
        result = dc.classify_from_context(
            string_literals=["proprietary algorithm"],
            env_var_access=[],
            parameter_names=[],
            variable_names=["trade_secret"],
        )
        assert "INTELLECTUAL_PROPERTY" in result.categories

    def test_multiple_categories(self):
        dc = DataClassifier()
        result = dc.classify_from_context(
            string_literals=["/etc/shadow"],
            env_var_access=["os.getenv('SECRET_KEY')"],
            parameter_names=["ssn"],
            variable_names=["credit_card"],
        )
        assert len(result.categories) >= 3
        assert "CREDENTIALS" in result.categories
        assert "PII" in result.categories
        assert "SYSTEM_DATA" in result.categories

    def test_classify_finding_evidence(self):
        dc = DataClassifier()
        result = dc.classify_finding_evidence(
            ["Reads password from config", "Sends api_key to external server"]
        )
        assert "CREDENTIALS" in result.categories

    def test_summary(self):
        dc = DataClassifier()
        result = dc.classify_from_context(
            string_literals=[],
            env_var_access=[],
            parameter_names=["password"],
            variable_names=[],
        )
        assert "CREDENTIALS" in result.summary

    def test_empty_summary(self):
        result = DataClassification()
        assert result.summary == "no sensitive data detected"
