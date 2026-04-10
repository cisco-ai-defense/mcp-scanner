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

"""
PyPI Package Scanner — Docker-sandboxed analysis of PyPI packages.

Downloads a PyPI package inside an isolated Docker container and runs
behavioral analysis and vulnerable packages audit. Docker is mandatory;
untrusted packages must never be extracted on the host.
"""

import json
import os
import subprocess
import sys
import tempfile
from importlib import resources
from typing import Optional

from ..config.constants import MCPScannerConstants as CONSTANTS
from ..utils.logging_config import get_logger

logger = get_logger(__name__)


class DockerNotAvailableError(Exception):
    """Raised when Docker is not installed or not running."""


class PyPIScanError(Exception):
    """Raised when the PyPI scan fails."""


class PyPIPackageScanner:
    """Scan PyPI packages inside an isolated Docker container.

    Downloads the package source distribution, extracts it, and runs
    behavioral analysis + vulnerable packages audit — all inside Docker.

    Example:
        >>> scanner = PyPIPackageScanner()
        >>> results = scanner.scan_package("flask")
        >>> print(results["total_findings"])
    """

    def __init__(
        self,
        image_name: Optional[str] = None,
        image_tag: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self._image_name = image_name or CONSTANTS.DOCKER_IMAGE_NAME
        self._image_tag = image_tag or CONSTANTS.DOCKER_IMAGE_TAG
        self._timeout = timeout or CONSTANTS.PYPI_SCAN_TIMEOUT
        self._full_image = f"{self._image_name}:{self._image_tag}"

    def check_docker(self) -> None:
        """Verify Docker is installed and running.

        Raises:
            DockerNotAvailableError: If Docker is not available.
        """
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise DockerNotAvailableError(
                    "Docker is installed but not running. "
                    "Please start Docker Desktop or the Docker daemon.\n"
                    f"Error: {result.stderr.strip()}"
                )
        except FileNotFoundError:
            raise DockerNotAvailableError(
                "Docker is not installed. "
                "PyPI package scanning requires Docker for sandboxed execution. "
                "Install Docker from https://docs.docker.com/get-docker/"
            )
        except subprocess.TimeoutExpired:
            raise DockerNotAvailableError(
                "Docker did not respond within 10 seconds. "
                "Please check that Docker is running properly."
            )

    def _image_exists(self) -> bool:
        """Check if the scanner Docker image already exists."""
        result = subprocess.run(
            ["docker", "image", "inspect", self._full_image],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def build_image(self, force: bool = False) -> None:
        """Build the scanner Docker image if it doesn't exist.

        Args:
            force: Rebuild even if the image already exists.
        """
        if not force and self._image_exists():
            logger.info("Docker image %s already exists, skipping build", self._full_image)
            return

        logger.info("Building Docker image %s ...", self._full_image)

        docker_dir = resources.files("mcpscanner.docker")
        dockerfile_path = str(docker_dir / "Dockerfile")
        context_dir = str(docker_dir)

        # Resources might be in a zip; extract to a temp dir if needed
        with resources.as_file(docker_dir) as ctx_path:
            cmd = [
                "docker", "build",
                "-t", self._full_image,
                "-f", str(ctx_path / "Dockerfile"),
                str(ctx_path),
            ]

            logger.debug("Running: %s", " ".join(cmd))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode != 0:
                raise PyPIScanError(
                    f"Failed to build Docker image:\n{result.stderr.strip()}"
                )

        logger.info("Docker image %s built successfully", self._full_image)

    def scan_package(
        self,
        package: str,
        version: Optional[str] = None,
        verbose: bool = False,
    ) -> dict:
        """Scan a PyPI package inside a Docker container.

        Args:
            package: PyPI package name (e.g., "flask").
            version: Specific version to scan (default: latest).
            verbose: Print container stderr to host stderr.

        Returns:
            Dictionary with scan results.

        Raises:
            DockerNotAvailableError: If Docker is not available.
            PyPIScanError: If the scan fails.
        """
        self.check_docker()
        self.build_image()

        cmd = [
            "docker", "run",
            "--rm",
            "--network=bridge",
        ]

        env_vars = {
            "LLM_API_KEY": os.environ.get("MCP_SCANNER_LLM_API_KEY", ""),
            "LLM_MODEL": os.environ.get("MCP_SCANNER_LLM_MODEL", "gpt-4o-mini"),
            "LLM_BASE_URL": os.environ.get("MCP_SCANNER_LLM_BASE_URL", ""),
            "LLM_API_VERSION": os.environ.get("MCP_SCANNER_LLM_API_VERSION", ""),
        }
        for key, value in env_vars.items():
            if value:
                cmd.extend(["-e", f"{key}={value}"])

        cmd.append(self._full_image)
        cmd.append(package)
        if version:
            cmd.extend(["--version", version])

        spec = f"{package}=={version}" if version else package
        logger.info("Scanning PyPI package: %s", spec)
        logger.debug("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            raise PyPIScanError(
                f"Scan timed out after {self._timeout}s. "
                f"Increase timeout via MCP_SCANNER_PYPI_SCAN_TIMEOUT env var."
            )

        if verbose and result.stderr:
            print(result.stderr, file=sys.stderr)

        if not result.stdout.strip():
            raise PyPIScanError(
                f"No output from container. stderr:\n{result.stderr.strip()}"
            )

        try:
            scan_results = json.loads(result.stdout.strip())
        except json.JSONDecodeError as e:
            raise PyPIScanError(
                f"Invalid JSON from container: {e}\n"
                f"stdout: {result.stdout[:500]}\n"
                f"stderr: {result.stderr[:500]}"
            )

        if "error" in scan_results and scan_results.get("is_safe") is None:
            raise PyPIScanError(
                f"Scan failed inside container: {scan_results['error']}"
            )

        return scan_results
