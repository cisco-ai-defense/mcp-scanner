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

"""Network egress policy enforcement.

Checks URLs and domains found in MCP tool code against an allow/deny list.
Policy is loaded from a JSON configuration file.

Example policy JSON:
{
    "mode": "deny",
    "deny_domains": ["evil.com", "*.attacker.io"],
    "deny_ips": ["198.51.100.0/24"],
    "allow_domains": ["api.github.com", "*.amazonaws.com"],
    "allow_ips": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}
"""

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from ...utils.logging_config import get_logger

logger = get_logger(__name__)

_URL_RE = re.compile(r"https?://[^\s\"'`\)]+")
_DOMAIN_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)


@dataclass
class NetworkPolicyViolation:
    """A single egress policy violation."""

    destination: str
    reason: str
    severity: str = "HIGH"


@dataclass
class NetworkPolicyConfig:
    """Parsed network policy configuration."""

    mode: str = "deny"  # "deny" = block deny list; "allow" = only permit allow list
    deny_domains: List[str] = field(default_factory=list)
    deny_ips: List[str] = field(default_factory=list)
    allow_domains: List[str] = field(default_factory=list)
    allow_ips: List[str] = field(default_factory=list)


class NetworkPolicy:
    """Evaluates URLs and domains against an egress policy."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize with optional JSON config file path.

        Args:
            config_path: Path to JSON policy file. If None, a permissive default is used.
        """
        self._config = NetworkPolicyConfig()
        if config_path:
            self._load_config(config_path)

    def _load_config(self, path: str) -> None:
        try:
            data = json.loads(Path(path).read_text())
            self._config = NetworkPolicyConfig(
                mode=data.get("mode", "deny"),
                deny_domains=data.get("deny_domains", []),
                deny_ips=data.get("deny_ips", []),
                allow_domains=data.get("allow_domains", []),
                allow_ips=data.get("allow_ips", []),
            )
            logger.debug(f"Loaded network policy from {path}")
        except Exception as e:
            logger.warning(f"Failed to load network policy from {path}: {e}")

    @property
    def is_configured(self) -> bool:
        """Return True if a non-empty policy was loaded."""
        cfg = self._config
        return bool(
            cfg.deny_domains or cfg.deny_ips or cfg.allow_domains or cfg.allow_ips
        )

    def check_strings(self, strings: List[str]) -> List[NetworkPolicyViolation]:
        """Check a list of string literals for policy violations.

        Args:
            strings: String literals extracted from code

        Returns:
            List of violations found
        """
        if not self.is_configured:
            return []

        violations: List[NetworkPolicyViolation] = []
        seen_destinations: set = set()

        for s in strings:
            for url_match in _URL_RE.finditer(s):
                url = url_match.group(0)
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or ""
                except Exception:
                    continue

                if host and host not in seen_destinations:
                    seen_destinations.add(host)
                    v = self._check_host(host)
                    if v:
                        violations.append(v)

        return violations

    def _check_host(self, host: str) -> Optional[NetworkPolicyViolation]:
        """Check a single host against the policy."""
        cfg = self._config

        # Try to parse as IP
        try:
            ip = ipaddress.ip_address(host)
            return self._check_ip(ip)
        except ValueError:
            pass

        # It's a domain
        return self._check_domain(host)

    def _check_domain(self, domain: str) -> Optional[NetworkPolicyViolation]:
        cfg = self._config

        if cfg.mode == "allow":
            # Only explicitly allowed domains pass
            if not self._domain_matches_any(domain, cfg.allow_domains):
                return NetworkPolicyViolation(
                    destination=domain,
                    reason=f"Domain not in allow list",
                )
        else:  # deny mode
            if self._domain_matches_any(domain, cfg.deny_domains):
                return NetworkPolicyViolation(
                    destination=domain,
                    reason=f"Domain matches deny list",
                )

        return None

    def _check_ip(
        self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> Optional[NetworkPolicyViolation]:
        cfg = self._config

        if cfg.mode == "allow":
            if not self._ip_in_any_network(ip, cfg.allow_ips):
                return NetworkPolicyViolation(
                    destination=str(ip),
                    reason=f"IP not in allow list",
                )
        else:
            if self._ip_in_any_network(ip, cfg.deny_ips):
                return NetworkPolicyViolation(
                    destination=str(ip),
                    reason=f"IP matches deny list",
                )

        return None

    @staticmethod
    def _domain_matches_any(domain: str, patterns: List[str]) -> bool:
        domain_lower = domain.lower()
        for pattern in patterns:
            if fnmatch.fnmatch(domain_lower, pattern.lower()):
                return True
        return False

    @staticmethod
    def _ip_in_any_network(
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address, networks: List[str]
    ) -> bool:
        for net_str in networks:
            try:
                network = ipaddress.ip_network(net_str, strict=False)
                if ip in network:
                    return True
            except ValueError:
                continue
        return False
