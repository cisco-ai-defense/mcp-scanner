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

"""Shared Docker image build and ``docker run`` hardening for package scanners."""

from __future__ import annotations

import os
from importlib import metadata, resources
from pathlib import Path
from typing import Dict, Tuple

# Pin the base image by digest for reproducible builds (python:3.13-alpine).
PYTHON_ALPINE_IMAGE = (
    "python:3.13-alpine"
    "@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
)


class DockerBuildError(Exception):
    """Raised when the scanner Docker image cannot be built."""


def installed_scanner_version() -> str:
    """Return the installed ``cisco-ai-mcp-scanner`` distribution version."""
    return metadata.version("cisco-ai-mcp-scanner")


def default_scanner_image_tag(*, ecosystem: str) -> str:
    """Default Docker image tag keyed to the installed scanner release.

    Using the package version instead of a mutable ``latest`` tag avoids
    silently reusing a stale image after ``pip install --upgrade``.

    Each package scanner reads only its own tag override env var so an
    npm-only override cannot change the PyPI image tag (and vice versa).
    """
    env_var_by_ecosystem = {
        "pypi": "MCP_SCANNER_DOCKER_IMAGE_TAG",
        "npm": "MCP_SCANNER_NPM_DOCKER_IMAGE_TAG",
    }
    env_var = env_var_by_ecosystem.get(ecosystem)
    if env_var is None:
        raise ValueError(
            f"unknown package scanner ecosystem {ecosystem!r}; "
            f"expected one of {sorted(env_var_by_ecosystem)}"
        )
    env_tag = os.getenv(env_var)
    if env_tag:
        return env_tag
    try:
        return installed_scanner_version()
    except metadata.PackageNotFoundError:
        return "latest"


def docker_run_hardening_flags() -> list[str]:
    """Return ``docker run`` flags that drop capabilities and bound resources.

    Package scanners execute untrusted archives (even when code is not run,
    parsers still touch hostile inputs), so both PyPI and npm images get
    the same baseline hardening.
    """
    return [
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=2g",
        "--cpus=2",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=512m",
        "--tmpfs",
        "/work:rw,noexec,nosuid,size=1g",
    ]


def prepare_docker_build(*, dockerfile: str) -> Tuple[Path, Path, Dict[str, str]]:
    """Resolve Docker build context, Dockerfile path, and build-args.

    When the scanner is run from a source checkout (``pyproject.toml`` sits
    next to the ``mcpscanner`` package), the image is built from that tree
    so the container matches the code on the host.

    When only the installed wheel is available, the Dockerfiles shipped via
    ``package-data`` are used with a pinned ``SCANNER_PACKAGE_VERSION`` so
    the container installs the same release the operator has locally.
    """
    docker_resource = resources.files("mcpscanner.docker")
    with resources.as_file(docker_resource) as docker_path:
        mcpscanner_pkg = Path(__file__).resolve().parent.parent
        project_root = mcpscanner_pkg.parent
        if (project_root / "pyproject.toml").exists():
            return (
                project_root,
                mcpscanner_pkg / "docker" / dockerfile,
                {"INSTALL_FROM_SOURCE": "1"},
            )

        wheel_dockerfile = (
            "Dockerfile.wheel"
            if dockerfile == "Dockerfile"
            else "Dockerfile.npm.wheel"
        )
        wheel_path = docker_path / wheel_dockerfile
        if not wheel_path.is_file():
            raise DockerBuildError(
                f"Docker assets missing from installed package "
                f"({wheel_dockerfile!r} not found). Reinstall "
                f"cisco-ai-mcp-scanner from a release that ships "
                f"mcpscanner.docker package-data, or run from a source "
                f"checkout so the image builds from the local tree."
            )

        try:
            version = installed_scanner_version()
        except metadata.PackageNotFoundError as exc:
            raise DockerBuildError(
                "cannot determine installed scanner version for Docker "
                "image build; install cisco-ai-mcp-scanner from PyPI or "
                "run from a source checkout"
            ) from exc

        return docker_path, wheel_path, {"SCANNER_PACKAGE_VERSION": version}
