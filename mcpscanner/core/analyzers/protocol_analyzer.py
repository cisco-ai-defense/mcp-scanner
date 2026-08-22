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

"""MCPS Protocol Security Analyzer for MCP Scanner.

Dynamically probes live MCP server endpoints for protocol-level security
controls. Complements static analyzers (code analysis) with runtime
protocol verification.

Checks:
    MCPS-001: Unencrypted HTTP transport (CWE-319)
    MCPS-002: Unauthenticated requests accepted (CWE-306)
    MCPS-003: No message signing detected (CWE-345)
    MCPS-004: No replay protection (CWE-294)
    MCPS-005: Tool definitions lack integrity hashes (CWE-494)
    MCPS-006: (removed -- handled by existing LLM/YARA analyzers)
    MCPS-007: Spoofed agent identity accepted (CWE-290)
    MCPS-008: Fail-open semantics (CWE-636)
    MCPS-009: No rate limiting (CWE-770)

References:
    OWASP MCP Security Cheat Sheet:
        https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
    OWASP AISVS C10 (MCP Security):
        https://github.com/OWASP/AISVS
"""

import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from mcp.types import LATEST_PROTOCOL_VERSION

from .base import BaseAnalyzer, SecurityFinding


class ProtocolAnalyzer(BaseAnalyzer):
    """Analyzes live MCP server endpoints for protocol-level security controls.

    Unlike static analyzers that examine source code, this analyzer connects
    to a running MCP server and probes its protocol-level security posture
    through JSON-RPC requests.
    """

    DEFAULT_PROTOCOL_VERSION = LATEST_PROTOCOL_VERSION
    PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
    SESSION_ID_HEADER = "MCP-Session-Id"

    def __init__(self, timeout: float = 10.0):
        """Initialize the protocol analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__("PROTOCOL")
        self.timeout = timeout

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze an MCP server endpoint for protocol security controls.

        Args:
            content: The target MCP server URL to probe.
            context: Optional context (unused).

        Returns:
            List of security findings from protocol-level checks.
        """
        target = content.strip()
        if not target.startswith("http"):
            target = "https://" + target

        findings: List[SecurityFinding] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=True,
            limits=httpx.Limits(max_connections=5),
        ) as client:
            init_response = await self._rpc(
                client,
                target,
                "initialize",
                {
                    "protocolVersion": self.DEFAULT_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-scanner-protocol", "version": "1.0"},
                },
            )
            protocol_version = self._get_protocol_version(init_response)
            session_id = self._get_session_id(init_response)
            session_headers = self._mcp_session_headers(protocol_version, session_id)

            if self._is_successful_response(init_response):
                await self._rpc(
                    client,
                    target,
                    "notifications/initialized",
                    request_id=None,
                    headers=session_headers,
                )

            # Gather data after the MCP lifecycle handshake. Stateful HTTP servers
            # can reject non-initialize requests that do not include the session ID.
            tools_response = await self._rpc(
                client,
                target,
                "tools/list",
                params={},
                headers=session_headers,
            )

            # Run all checks
            findings.extend(self._check_transport(target))
            findings.extend(self._check_auth(tools_response))
            findings.extend(self._check_signing(tools_response, init_response))
            findings.extend(await self._check_replay(client, target, session_headers))
            findings.extend(self._check_tool_integrity(tools_response))
            # Tool description scanning handled by existing analyzers (LLM, YARA)
            findings.extend(
                await self._check_spoofed_identity(client, target, session_headers)
            )
            findings.extend(
                await self._check_fail_open(client, target, session_headers)
            )
            findings.extend(
                await self._check_rate_limiting(client, target, session_headers)
            )

        return findings

    # ── JSON-RPC helper ─────────────────────────────────────────

    async def _rpc(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: Optional[Dict] = None,
        request_id: Optional[Any] = 1,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[httpx.Response]:
        """Send a JSON-RPC 2.0 request to the MCP server.

        Args:
            client: The HTTP client.
            url: The server URL.
            method: The JSON-RPC method name.
            params: Optional parameters.
            request_id: Optional request ID. Omit for notifications.
            headers: Optional additional HTTP headers.

        Returns:
            The HTTP response, or None on error.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if request_id is not None:
            payload["id"] = request_id
        if params is not None:
            payload["params"] = params

        try:
            resp = await client.post(
                url,
                json=payload,
                headers=self._json_rpc_headers(headers),
            )
            return resp
        except Exception as e:
            self.logger.debug(f"RPC call {method} failed: {e}")
            return None

    def _json_rpc_headers(
        self, extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """Build headers for MCP JSON-RPC HTTP requests."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _mcp_session_headers(
        self, protocol_version: Optional[str], session_id: Optional[str]
    ) -> Dict[str, str]:
        """Build MCP lifecycle headers for post-initialize HTTP requests."""
        headers = {}
        if protocol_version:
            headers[self.PROTOCOL_VERSION_HEADER] = protocol_version
        if session_id:
            headers[self.SESSION_ID_HEADER] = session_id
        return headers

    def _get_protocol_version(self, resp: Optional[httpx.Response]) -> str:
        """Return the negotiated protocol version from initialize."""
        body = self._parse_body(resp)
        if body and isinstance(body, dict):
            result = body.get("result", {})
            if isinstance(result, dict):
                protocol_version = result.get("protocolVersion")
                if isinstance(protocol_version, str) and protocol_version:
                    return protocol_version
        return self.DEFAULT_PROTOCOL_VERSION

    def _get_session_id(self, resp: Optional[httpx.Response]) -> Optional[str]:
        """Return the MCP HTTP session ID assigned during initialize."""
        if resp is None:
            return None
        return resp.headers.get(self.SESSION_ID_HEADER)

    def _is_successful_response(self, resp: Optional[httpx.Response]) -> bool:
        """Return True when a JSON-RPC response does not contain an error."""
        if resp is None or resp.status_code >= 400:
            return False

        body = self._parse_body(resp)
        return not (isinstance(body, dict) and body.get("error"))

    def _parse_body(self, resp: Optional[httpx.Response]) -> Any:
        """Parse a JSON-RPC response body, handling SSE format.

        Args:
            resp: The HTTP response.

        Returns:
            Parsed JSON body, or None on error.
        """
        if resp is None:
            return None
        try:
            ct = resp.headers.get("content-type", "").lower()
            if "text/event-stream" in ct:
                for line in resp.text.split("\n"):
                    if line.startswith("data: "):
                        try:
                            return json.loads(line[6:])
                        except json.JSONDecodeError:
                            continue
            return resp.json()
        except Exception:
            return None

    def _get_tools(self, resp: Optional[httpx.Response]) -> List[Dict]:
        """Extract tool list from a tools/list response.

        Args:
            resp: The HTTP response from tools/list.

        Returns:
            List of tool dictionaries.
        """
        body = self._parse_body(resp)
        if body and isinstance(body, dict):
            result = body.get("result", {})
            if isinstance(result, dict):
                return result.get("tools", [])
        return []

    # ── MCPS-001: Transport Security ────────────────────────────

    def _check_transport(self, target: str) -> List[SecurityFinding]:
        """Check if the server uses encrypted transport (HTTPS)."""
        parsed = urlparse(target)
        if parsed.scheme == "http":
            return [
                self.create_security_finding(
                    severity="HIGH",
                    summary="MCP server is accessible over unencrypted HTTP. "
                    "All JSON-RPC messages, tool arguments, and responses "
                    "are visible to network observers.",
                    threat_category="Unencrypted Transport",
                    details={
                        "check_id": "MCPS-001",
                        "cwe": "CWE-319",
                        "target": target,
                        "owasp_ref": "MCP Security Cheat Sheet Section 6",
                    },
                )
            ]
        return []

    # ── MCPS-002: Authentication ────────────────────────────────

    def _check_auth(
        self, tools_response: Optional[httpx.Response]
    ) -> List[SecurityFinding]:
        """Check if the server requires authentication."""
        if tools_response is None:
            return []

        if tools_response.status_code == 200:
            body = self._parse_body(tools_response)
            if body and not (isinstance(body, dict) and body.get("error")):
                return [
                    self.create_security_finding(
                        severity="HIGH",
                        summary="MCP server accepts unauthenticated requests. "
                        "Any caller can invoke tools without credentials.",
                        threat_category="Authentication Bypass",
                        details={
                            "check_id": "MCPS-002",
                            "cwe": "CWE-306",
                            "status_code": tools_response.status_code,
                            "owasp_ref": "MCP Security Cheat Sheet Section 6",
                        },
                    )
                ]
        return []

    # ── MCPS-003: Message Signing ───────────────────────────────

    def _check_signing(
        self,
        tools_response: Optional[httpx.Response],
        init_response: Optional[httpx.Response],
    ) -> List[SecurityFinding]:
        """Check if the server signs responses (MCPS or ATTP headers)."""
        signing_headers = [
            "x-mcps-signature",
            "x-attp-signature",
            "x-agent-signature",
        ]

        for resp in [tools_response, init_response]:
            if resp is None:
                continue
            for header in signing_headers:
                if header in resp.headers:
                    return []

        # Check capabilities for MCPS
        body = self._parse_body(init_response)
        if body and isinstance(body, dict):
            result = body.get("result", {})
            if isinstance(result, dict):
                caps = result.get("capabilities", {})
                if caps.get("mcps") or caps.get("signing"):
                    return []

        return [
            self.create_security_finding(
                severity="HIGH",
                summary="No message signing detected. Responses are not "
                "cryptographically signed. A network intermediary could "
                "modify tool results without detection.",
                threat_category="Missing Message Integrity",
                details={
                    "check_id": "MCPS-003",
                    "cwe": "CWE-345",
                    "owasp_ref": "MCP Security Cheat Sheet Section 7",
                    "aisvs_ref": "AISVS 10.4.11",
                },
            )
        ]

    # ── MCPS-004: Replay Protection ─────────────────────────────

    async def _check_replay(
        self,
        client: httpx.AsyncClient,
        target: str,
        session_headers: Optional[Dict[str, str]] = None,
    ) -> List[SecurityFinding]:
        """Check if the server rejects replayed requests."""
        payload = {
            "jsonrpc": "2.0",
            "id": "replay-check",
            "method": "tools/list",
            "params": {},
        }
        body = json.dumps(payload)

        try:
            r1 = await client.post(
                target,
                content=body,
                headers=self._json_rpc_headers(session_headers),
            )
            r2 = await client.post(
                target,
                content=body,
                headers=self._json_rpc_headers(session_headers),
            )

            if r1.status_code == 200 and r2.status_code == 200:
                return [
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary="Server accepts identical replayed requests. "
                        "No nonce or timestamp validation detected. An attacker "
                        "can capture and replay legitimate requests.",
                        threat_category="Missing Replay Protection",
                        details={
                            "check_id": "MCPS-004",
                            "cwe": "CWE-294",
                            "owasp_ref": "MCP Security Cheat Sheet Section 7",
                            "aisvs_ref": "AISVS 10.4.11",
                        },
                    )
                ]
        except Exception:
            pass
        return []

    # ── MCPS-005: Tool Integrity ────────────────────────────────

    def _check_tool_integrity(
        self, tools_response: Optional[httpx.Response]
    ) -> List[SecurityFinding]:
        """Check if tool definitions have integrity hashes."""
        tools = self._get_tools(tools_response)
        if not tools:
            return []

        for tool in tools:
            if isinstance(tool, dict):
                if tool.get("hash") or tool.get("integrity") or tool.get("signature"):
                    return []

        return [
            self.create_security_finding(
                severity="MEDIUM",
                summary=f"Tool definitions ({len(tools)} tools) lack integrity "
                f"hashes or signatures. An attacker could modify tool schemas "
                f"after initial approval (rug-pull attack).",
                threat_category="Missing Tool Integrity",
                details={
                    "check_id": "MCPS-005",
                    "cwe": "CWE-494",
                    "tool_count": len(tools),
                    "owasp_ref": "MCP Security Cheat Sheet Section 2",
                },
            )
        ]

    # MCPS-006 (Tool Poisoning) removed -- handled by existing LLM/YARA analyzers

    # ── MCPS-007: Spoofed Identity ──────────────────────────────

    async def _check_spoofed_identity(
        self,
        client: httpx.AsyncClient,
        target: str,
        session_headers: Optional[Dict[str, str]] = None,
    ) -> List[SecurityFinding]:
        """Check if the server accepts spoofed agent identity headers."""
        spoofed_headers = self._json_rpc_headers(session_headers)
        spoofed_headers.update(
            {
                "X-Agent-ID": "spoofed-admin-agent",
                "X-Agent-Role": "admin",
                "X-Agent-Trust-Level": "4",
            }
        )
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

        try:
            resp = await client.post(target, json=payload, headers=spoofed_headers)
            if resp.status_code == 200:
                body = self._parse_body(resp)
                if body and not (isinstance(body, dict) and body.get("error")):
                    return [
                        self.create_security_finding(
                            severity="HIGH",
                            summary="Server accepts spoofed agent identity headers "
                            "(X-Agent-ID, X-Agent-Role, X-Agent-Trust-Level) "
                            "without cryptographic verification.",
                            threat_category="Identity Spoofing",
                            details={
                                "check_id": "MCPS-007",
                                "cwe": "CWE-290",
                                "owasp_ref": "MCP Security Cheat Sheet Section 6",
                                "aisvs_ref": "AISVS 10.2.13",
                            },
                        )
                    ]
        except Exception:
            pass
        return []

    # ── MCPS-008: Fail-Open Semantics ───────────────────────────

    async def _check_fail_open(
        self,
        client: httpx.AsyncClient,
        target: str,
        session_headers: Optional[Dict[str, str]] = None,
    ) -> List[SecurityFinding]:
        """Check if the server fails open on invalid input."""
        invalid_payloads = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "../../../../etc/passwd", "arguments": {}},
            },
            {"not_jsonrpc": True},
            "this is not json",
        ]

        for payload in invalid_payloads:
            try:
                if isinstance(payload, str):
                    resp = await client.post(
                        target,
                        content=payload,
                        headers=self._json_rpc_headers(session_headers),
                    )
                else:
                    resp = await client.post(
                        target,
                        json=payload,
                        headers=self._json_rpc_headers(session_headers),
                    )

                if resp.status_code == 200:
                    body = self._parse_body(resp)
                    if body and isinstance(body, dict) and body.get("result"):
                        return [
                            self.create_security_finding(
                                severity="MEDIUM",
                                summary="Server processes invalid or malformed "
                                "requests instead of rejecting them. Fail-open "
                                "semantics detected.",
                                threat_category="Fail-Open Semantics",
                                details={
                                    "check_id": "MCPS-008",
                                    "cwe": "CWE-636",
                                    "owasp_ref": "MCP Security Cheat Sheet Section 7",
                                    "aisvs_ref": "AISVS 10.6.4",
                                },
                            )
                        ]
            except Exception:
                continue
        return []

    # ── MCPS-009: Rate Limiting ─────────────────────────────────

    async def _check_rate_limiting(
        self,
        client: httpx.AsyncClient,
        target: str,
        session_headers: Optional[Dict[str, str]] = None,
    ) -> List[SecurityFinding]:
        """Check if the server enforces rate limiting."""
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        accepted = 0
        rate_limited = False

        for _ in range(10):
            try:
                resp = await client.post(
                    target,
                    json=payload,
                    headers=self._json_rpc_headers(session_headers),
                )
                if resp.status_code == 429:
                    rate_limited = True
                    break
                if resp.status_code == 200:
                    accepted += 1
            except Exception:
                break

        if not rate_limited and accepted >= 10:
            return [
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=f"No rate limiting detected. All {accepted} rapid "
                    f"requests were accepted. Server is vulnerable to "
                    f"resource exhaustion and denial of service.",
                    threat_category="Missing Rate Limiting",
                    details={
                        "check_id": "MCPS-009",
                        "cwe": "CWE-770",
                        "requests_accepted": accepted,
                        "owasp_ref": "MCP Security Cheat Sheet Section 6",
                    },
                )
            ]
        return []
