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

"""Regression tests for the dependency policy in pyproject.toml."""

import re
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = ROOT / "mcpscanner" / "docker"
DOCKER_LOCK = DOCKER_DIR / "requirements.lock.txt"


def _project_requirements() -> dict[str, Requirement]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    reqs = [Requirement(r) for r in pyproject["project"]["dependencies"]]
    return {canonicalize_name(r.name): r for r in reqs}


def _docker_lock_pins() -> dict[str, str]:
    pins = re.findall(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)",
        DOCKER_LOCK.read_text(),
        flags=re.MULTILINE,
    )
    return {canonicalize_name(name): version for name, version in pins}


@pytest.mark.parametrize(
    "version, allowed",
    [
        ("1.29.1", False),  # GHSA-84m7-p3x7-pcfv and older advisories
        ("1.30.0", True),
        ("2.0.0", False),  # GHSA-84m7-p3x7-pcfv
        ("2.0.1", False),
        ("2.1.0", False),
        ("2.1.1", False),
        ("2.2.0", True),
        ("2.3.0", True),
        ("3.0.0", False),
    ],
)
def test_mcp_sdk_range(version, allowed):
    assert _project_requirements()["mcp"].specifier.contains(version) is allowed


@pytest.mark.parametrize(
    "version, allowed",
    [
        ("1.91.4", False),  # CVE-2026-84377
        ("1.91.5", True),
        ("1.92.0", False),
        ("1.92.1", False),
        ("1.92.2", True),
        ("1.93.0", False),
        ("1.93.1", False),
        ("1.93.2", True),
        ("1.94.0", False),
        ("1.94.1", False),
        ("1.94.2", False),
        ("1.94.3", True),
        ("1.95.0", False),
        ("1.95.1", True),
        ("1.96.0", False),
        ("1.96.1", False),
        ("1.96.2", True),
        ("1.106.2", True),
        ("1.107.0", False),  # hijacked release, BerriAI/litellm#47826
        ("2.0.0", False),
    ],
)
def test_litellm_range(version, allowed):
    assert _project_requirements()["litellm"].specifier.contains(version) is allowed


def test_runtime_dependencies_use_ranges_with_ceilings():
    for name, req in _project_requirements().items():
        operators = {spec.operator for spec in req.specifier}
        assert "==" not in operators, f"{name} is pinned exactly"
        assert "<" in operators, f"{name} has no upper bound"


def test_docker_lock_satisfies_project_requirements():
    pins = _docker_lock_pins()
    for name, req in _project_requirements().items():
        assert name in pins, f"{name} missing from {DOCKER_LOCK.name}"
        assert req.specifier.contains(pins[name]), (
            f"{DOCKER_LOCK.name} pins {name}=={pins[name]}, outside {req.specifier}"
        )


@pytest.mark.parametrize(
    "dockerfile",
    ["Dockerfile", "Dockerfile.npm", "Dockerfile.wheel", "Dockerfile.npm.wheel"],
)
def test_dockerfiles_install_the_hash_pinned_lock(dockerfile):
    text = (DOCKER_DIR / dockerfile).read_text()
    assert "--require-hashes" in text and "requirements.lock.txt" in text
    installs = re.findall(r"pip install [^;&]*cisco-ai-mcp-scanner|pip install [^;&]*\s\.;", text)
    assert installs, f"{dockerfile} does not install the scanner"
    assert all("--no-deps" in line for line in installs), installs
    assert "pip check" in text
