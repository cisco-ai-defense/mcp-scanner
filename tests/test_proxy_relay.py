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

from unittest.mock import patch

import pytest

from mcpscanner.utils.proxy_relay import (
    ENV_PROXY_RELAY_URL,
    HEADER_CONNECTOR_ID,
    HEADER_DESTINATION_URL,
    HEADER_STREAMING,
    HEADER_TENANT_ID,
    NIL_CONNECTOR_ID,
    _normalized_proxy_relay_url,
    is_hybrid_connector_id,
    prepare_mcp_dial,
    proxy_relay_dial_url,
    proxy_relay_headers,
)


class TestIsHybridConnectorID:
    def test_empty_is_saas(self):
        assert is_hybrid_connector_id(None) is False
        assert is_hybrid_connector_id("") is False
        assert is_hybrid_connector_id("   ") is False

    def test_nil_uuid_is_saas(self):
        assert is_hybrid_connector_id(NIL_CONNECTOR_ID) is False

    def test_real_connector_is_hybrid(self):
        assert is_hybrid_connector_id("42cab0eb-3d55-4097-b0db-1ae5099da63b") is True


class TestProxyRelayHeaders:
    def test_saas_returns_headers_unchanged(self):
        headers = {"User-Agent": "test"}
        out = proxy_relay_headers(
            "http://example.com/sse",
            headers,
            connector_id=None,
            tenant_id=None,
        )
        assert out == headers

    @patch(
        "mcpscanner.utils.proxy_relay.proxy_relay_dial_url",
        return_value="http://proxy-relay:5600",
    )
    def test_hybrid_injects_routing_headers(self, _mock_dial_url):
        headers = {"User-Agent": "test"}
        out = proxy_relay_headers(
            "http://host.docker.internal:8765/success",
            headers,
            connector_id="42cab0eb-3d55-4097-b0db-1ae5099da63b",
            tenant_id="192caeea-9955-44a9-8ef4-19006f5beb10",
            streaming=True,
        )
        assert out[HEADER_DESTINATION_URL] == "http://host.docker.internal:8765/success"
        assert out[HEADER_CONNECTOR_ID] == "42cab0eb-3d55-4097-b0db-1ae5099da63b"
        assert out[HEADER_TENANT_ID] == "192caeea-9955-44a9-8ef4-19006f5beb10"
        assert out[HEADER_STREAMING] == "true"
        assert out["User-Agent"] == "test"


class TestPrepareMcpDial:
    @patch(
        "mcpscanner.utils.proxy_relay.proxy_relay_dial_url",
        return_value="http://proxy-relay:5600",
    )
    def test_saas_uses_direct_url(self, _mock_dial_url):
        dial_url, headers = prepare_mcp_dial(
            "https://public.example.com/sse",
            {},
            connector_id=None,
            tenant_id=None,
        )
        assert dial_url == "https://public.example.com/sse"
        assert headers == {}

    @patch(
        "mcpscanner.utils.proxy_relay.proxy_relay_dial_url",
        return_value="http://proxy-relay:5600",
    )
    def test_hybrid_uses_relay(self, _mock_dial_url):
        destination = "http://host.docker.internal:8765/success"
        dial_url, headers = prepare_mcp_dial(
            destination,
            {},
            connector_id="42cab0eb-3d55-4097-b0db-1ae5099da63b",
            tenant_id="tenant-1",
            streaming=True,
        )
        assert dial_url == "http://proxy-relay:5600"
        assert headers[HEADER_DESTINATION_URL] == destination


class TestNormalizedProxyRelayURL:
    def test_missing_env_raises(self, monkeypatch):
        monkeypatch.delenv(ENV_PROXY_RELAY_URL, raising=False)
        with pytest.raises(RuntimeError, match=f"{ENV_PROXY_RELAY_URL} is not configured"):
            _normalized_proxy_relay_url()

    def test_scheme_less_defaults_to_http(self, monkeypatch):
        monkeypatch.setenv(ENV_PROXY_RELAY_URL, "cloud-gateway:5600")
        assert _normalized_proxy_relay_url() == "http://cloud-gateway:5600"
        assert proxy_relay_dial_url() == "http://cloud-gateway:5600"

    def test_explicit_http_preserved(self, monkeypatch):
        monkeypatch.setenv(ENV_PROXY_RELAY_URL, "http://cloud-gateway:5600")
        assert _normalized_proxy_relay_url() == "http://cloud-gateway:5600"

    def test_explicit_https_preserved(self, monkeypatch):
        monkeypatch.setenv(ENV_PROXY_RELAY_URL, "https://relay.example.com")
        assert _normalized_proxy_relay_url() == "https://relay.example.com"
