# Copyright 2026 Cisco Systems, Inc.
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
"""Lint configuration loader (YAML-based)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class LintConfig:
    """Configuration for the MCP schema linter."""

    extends: str = "recommended"
    rules: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str) -> "LintConfig":
        """Load lint configuration from a YAML file."""
        import yaml  # deferred import — yaml is optional

        config_path = Path(path)
        if not config_path.is_file():
            logger.warning("Lint config file not found: %s", path)
            return cls()

        with open(config_path) as f:
            data: Dict[str, Any] = yaml.safe_load(f) or {}

        return cls(
            extends=data.get("extends", "recommended"),
            rules=data.get("rules", {}),
        )

    @classmethod
    def default(cls) -> "LintConfig":
        return cls()

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "LintConfig":
        if config_path:
            return cls.from_file(config_path)
        return cls.default()
