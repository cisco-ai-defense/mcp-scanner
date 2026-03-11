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

"""Filesystem boundary policy enforcement.

Checks file paths found in MCP tool code against an allowed-directories list.
Policy is loaded from a JSON configuration file.

Example policy JSON:
{
    "allowed_directories": ["/tmp", "/data", "/app/uploads"],
    "denied_paths": ["/etc/shadow", "/etc/passwd", "~/.ssh"],
    "deny_traversal": true
}
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import List, Optional

from ...utils.logging_config import get_logger

logger = get_logger(__name__)

_PATH_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\")
_ABSOLUTE_PATH_RE = re.compile(r"(?:^|[\"' (=])(/[a-zA-Z][\w./\-]*)")
_HOME_DIR_RE = re.compile(r"~[/\\]")


@dataclass
class FilesystemPolicyViolation:
    """A single filesystem policy violation."""

    path: str
    reason: str
    severity: str = "MEDIUM"


@dataclass
class FilesystemPolicyConfig:
    """Parsed filesystem policy configuration."""

    allowed_directories: List[str] = field(default_factory=list)
    denied_paths: List[str] = field(default_factory=list)
    deny_traversal: bool = True


class FilesystemPolicy:
    """Evaluates file paths against a filesystem boundary policy."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize with optional JSON config file path.

        Args:
            config_path: Path to JSON policy file. If None, only traversal detection is active.
        """
        self._config = FilesystemPolicyConfig()
        if config_path:
            self._load_config(config_path)

    def _load_config(self, path: str) -> None:
        try:
            data = json.loads(Path(path).read_text())
            self._config = FilesystemPolicyConfig(
                allowed_directories=data.get("allowed_directories", []),
                denied_paths=data.get("denied_paths", []),
                deny_traversal=data.get("deny_traversal", True),
            )
            logger.debug(f"Loaded filesystem policy from {path}")
        except Exception as e:
            logger.warning(f"Failed to load filesystem policy from {path}: {e}")

    @property
    def is_configured(self) -> bool:
        """Return True if a non-empty policy was loaded."""
        cfg = self._config
        return bool(cfg.allowed_directories or cfg.denied_paths)

    def check_strings(self, strings: List[str]) -> List[FilesystemPolicyViolation]:
        """Check string literals for filesystem policy violations.

        Args:
            strings: String literals extracted from code

        Returns:
            List of violations found
        """
        violations: List[FilesystemPolicyViolation] = []
        seen_paths: set = set()

        for s in strings:
            # Check for path traversal
            if self._config.deny_traversal and _PATH_TRAVERSAL_RE.search(s):
                if s not in seen_paths:
                    seen_paths.add(s)
                    violations.append(
                        FilesystemPolicyViolation(
                            path=s[:120],
                            reason="Path traversal pattern detected (../)",
                            severity="HIGH",
                        )
                    )

            # Check absolute paths
            for match in _ABSOLUTE_PATH_RE.finditer(s):
                path_str = match.group(1)
                if path_str in seen_paths:
                    continue
                seen_paths.add(path_str)

                v = self._check_path(path_str)
                if v:
                    violations.append(v)

            # Check home directory references
            if _HOME_DIR_RE.search(s):
                if "~/" not in seen_paths:
                    seen_paths.add("~/")
                    v = self._check_path_against_denied(s[:120])
                    if v:
                        violations.append(v)

        return violations

    def _check_path(self, path_str: str) -> Optional[FilesystemPolicyViolation]:
        """Check a single path against the policy."""
        # Check denied paths first
        denied = self._check_path_against_denied(path_str)
        if denied:
            return denied

        # Check allowed directories
        if self._config.allowed_directories:
            if not self._path_in_allowed(path_str):
                return FilesystemPolicyViolation(
                    path=path_str,
                    reason="Path outside allowed directories",
                )

        return None

    def _check_path_against_denied(
        self, path_str: str
    ) -> Optional[FilesystemPolicyViolation]:
        cfg = self._config
        path_lower = path_str.lower()

        for denied in cfg.denied_paths:
            denied_lower = denied.lower()
            if path_lower.startswith(denied_lower) or denied_lower in path_lower:
                return FilesystemPolicyViolation(
                    path=path_str,
                    reason=f"Path matches denied pattern: {denied}",
                    severity="HIGH",
                )
        return None

    def _path_in_allowed(self, path_str: str) -> bool:
        """Check if path falls under any allowed directory."""
        try:
            normalized = PurePosixPath(path_str)
        except Exception:
            return False

        for allowed in self._config.allowed_directories:
            try:
                allowed_path = PurePosixPath(allowed)
                if normalized == allowed_path or allowed_path in normalized.parents:
                    return True
            except Exception:
                continue

        return False
