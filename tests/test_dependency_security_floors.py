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

"""Guard the security floors of the litellm and mcp runtime requirements."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _requirement(name: str) -> Requirement:
    deps = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"][
        "dependencies"
    ]
    for dep in deps:
        req = Requirement(dep)
        if req.name == name:
            return req
    raise AssertionError(f"{name} is not a runtime dependency")


# Releases inside an open advisory range (or hijacked) that the specifier must reject.
LITELLM_REJECTED = [
    "1.93.2",  # GHSA-g5ff-637f-6q2m, GHSA-7hp6-4w63-5g45, GHSA-w4c7-34wj-hqm8
    "1.95.0",  # GHSA-3cv6-jpf6-8222 (re-introduced), GHSA-7hp6-4w63-5g45
    "1.100.3",  # GHSA-7hp6-4w63-5g45
    "1.103.0",  # GHSA-7hp6-4w63-5g45
    "1.103.9",  # GHSA-w4c7-34wj-hqm8
    *[f"1.104.{n}" for n in range(8)],  # GHSA-w4c7-34wj-hqm8, fixed in 1.104.8
    *[f"1.105.{n}" for n in range(6)],  # GHSA-w4c7-34wj-hqm8, fixed in 1.105.6
    *[f"1.106.{n}" for n in range(5)],  # GHSA-w4c7-34wj-hqm8, fixed in 1.106.5
    "1.107.0",  # hijacked PyPI upload, BerriAI/litellm#47826
    "2.0.0",  # next major, untested
]

LITELLM_ACCEPTED = ["1.103.10", "1.104.8", "1.105.6", "1.105.7", "1.106.5", "1.106.6"]


@pytest.mark.parametrize("version", LITELLM_REJECTED)
def test_litellm_specifier_rejects_vulnerable_releases(version: str) -> None:
    assert not _requirement("litellm").specifier.contains(Version(version))


@pytest.mark.parametrize("version", LITELLM_ACCEPTED)
def test_litellm_specifier_accepts_fixed_releases(version: str) -> None:
    assert _requirement("litellm").specifier.contains(Version(version))


@pytest.mark.parametrize("version", ["1.30.0", "2.0.0", "2.1.1"])
def test_mcp_specifier_rejects_pre_2_2(version: str) -> None:
    # 2.0.0-2.1.1 carry GHSA-84m7-p3x7-pcfv, GHSA-w4fh-qvv9-3v23,
    # GHSA-5h93-6whr-6q8j and GHSA-rwrf-2pqf-9j8j; 1.x lacks server/discover.
    assert not _requirement("mcp").specifier.contains(Version(version))


@pytest.mark.parametrize("version", ["2.2.0", "2.3.0"])
def test_mcp_specifier_accepts_fixed_releases(version: str) -> None:
    assert _requirement("mcp").specifier.contains(Version(version))
