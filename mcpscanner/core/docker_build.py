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

from importlib import metadata, resources
from pathlib import Path
from typing import Dict, Tuple


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
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=512m",
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
        build_args: Dict[str, str] = {}
        try:
            build_args["SCANNER_PACKAGE_VERSION"] = metadata.version(
                "cisco-ai-mcp-scanner"
            )
        except metadata.PackageNotFoundError:
            pass
        return docker_path, docker_path / wheel_dockerfile, build_args
