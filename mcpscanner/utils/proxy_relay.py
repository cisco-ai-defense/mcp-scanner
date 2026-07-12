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

"""Proxy relay routing helpers for hybrid (private connector) MCP access.

Mirrors ai-firewall-services/mcp_scan_worker/proxy_relay.py so live security
scans can reach private MCP servers through cloud-gateway proxy relay.
"""

from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

HEADER_DESTINATION_URL = "x-aid-destination-url"
HEADER_CONNECTOR_ID = "x-aid-connector-id"
HEADER_TENANT_ID = "x-aid-tenant-id"
HEADER_STREAMING = "X-Aid-Streaming"
ENV_PROXY_RELAY_URL = "PROXY_RELAY_URL"

# Aligns with mcp_registry/connectorutil dummy / nil connector IDs.
NIL_CONNECTOR_ID = "00000000-0000-0000-0000-000000000000"


def is_hybrid_connector_id(connector_id: Optional[str]) -> bool:
    """Return True when connector_id denotes a private (hybrid) data plane."""
    connector_id = (connector_id or "").strip()
    if not connector_id:
        return False
    return connector_id != NIL_CONNECTOR_ID


def _normalized_proxy_relay_url() -> str:
    """Return PROXY_RELAY_URL with an explicit scheme.

    Scheme-less values default to ``http://`` to match
    ``mcp_scan_worker/proxy_relay.py`` and in-cluster Helm config
    (``host:port`` on the pod network, not the public internet).
    """
    proxy_relay_url = os.environ.get(ENV_PROXY_RELAY_URL, "").strip()
    if not proxy_relay_url:
        raise RuntimeError(
            f"{ENV_PROXY_RELAY_URL} is not configured for hybrid MCP access"
        )
    if not proxy_relay_url.startswith(("http://", "https://")):
        proxy_relay_url = f"http://{proxy_relay_url}"
    return proxy_relay_url


def proxy_relay_dial_url() -> str:
    """Return the proxy relay endpoint to dial for hybrid requests."""
    return _normalized_proxy_relay_url()


def proxy_relay_headers(
    destination_url: str,
    headers: Dict[str, str],
    connector_id: Optional[str],
    tenant_id: Optional[str],
    *,
    streaming: bool = False,
) -> Dict[str, str]:
    """Inject proxy-relay routing headers for hybrid (connector) requests."""
    if not is_hybrid_connector_id(connector_id):
        return headers

    connector_id = (connector_id or "").strip()
    out_headers = dict(headers)
    out_headers[HEADER_DESTINATION_URL] = destination_url
    out_headers[HEADER_CONNECTOR_ID] = connector_id
    if tenant_id:
        out_headers[HEADER_TENANT_ID] = tenant_id.strip()
    if streaming:
        out_headers[HEADER_STREAMING] = "true"
    return out_headers


def prepare_mcp_dial(
    server_url: str,
    headers: Dict[str, str],
    connector_id: Optional[str],
    tenant_id: Optional[str],
    *,
    streaming: bool = False,
) -> Tuple[str, Dict[str, str]]:
    """Return the MCP client dial URL and headers for SaaS or hybrid routing."""
    out_headers = proxy_relay_headers(
        server_url,
        headers,
        connector_id,
        tenant_id,
        streaming=streaming,
    )
    if is_hybrid_connector_id(connector_id):
        return proxy_relay_dial_url(), out_headers
    return server_url, out_headers
