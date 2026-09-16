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

"""Shared Docker plumbing and entrypoints for package scanners.

``PyPIPackageScanner`` and ``NPMPackageScanner`` differ in where they fetch a
package and how they parse it, but they reach it the same way: build a
hardened container image, or refuse to run in-process from inside an event
loop. Both halves used to be duplicated verbatim, which mattered most for the
container hardening flags — a flag added to one scanner silently left the
other unhardened.
"""

from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass
from typing import ClassVar, Optional

from ..config.config import Config
from ..utils.logging_config import get_logger
from .docker_build import (
    DockerBuildError,
    default_scanner_image_tag,
    prepare_docker_build,
)
from .package_sandbox import redact_argv_for_logging

logger = get_logger(__name__)


class DockerNotAvailableError(Exception):
    """Raised when Docker is not installed or not running."""


@dataclass(frozen=True)
class EcosystemProfile:
    """The ecosystem-specific names the shared Docker plumbing needs.

    Error text is carried here rather than generated so each scanner keeps
    the exact wording its callers already match on.
    """

    #: Short ecosystem key, also the image-tag discriminator ("pypi", "npm").
    name: str
    #: Dockerfile to build, relative to the packaged docker context.
    dockerfile: str
    #: Image name used when the caller does not override it.
    default_image_name: str
    #: Per-scan timeout in seconds for Docker mode.
    default_timeout: int
    #: Exception type raised for this ecosystem's scan failures.
    scan_error: type[Exception]
    #: Remediation sentence appended when the docker binary is missing.
    docker_missing_hint: str
    #: Remediation sentence appended when ``docker info`` times out.
    docker_unresponsive_hint: str
    #: Subject of the "failed to build" message, e.g. "npm Docker image".
    build_failure_subject: str


def assert_loop_not_running(context: str) -> None:
    """Refuse to call ``asyncio.run`` from inside an already-running loop.

    The original implementation called ``asyncio.run`` unconditionally,
    which crashed every SDK caller that lived inside an event loop (FastAPI
    handlers, jupyter cells, etc.). The async entrypoint is the supported
    alternative; raise a clear error rather than silently deadlocking.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(
        f"{context} was called from inside a running asyncio event loop. "
        f"Use the async entrypoint (e.g. await scan_package_async(...)) "
        f"or run this call from a non-async context."
    )


class PackageScannerBase:
    """Docker lifecycle and entrypoint dispatch shared by package scanners.

    Subclasses declare a :class:`EcosystemProfile` and implement the three
    ecosystem-specific steps: name validation, the container invocation, and
    the in-process fallback.
    """

    PROFILE: ClassVar[EcosystemProfile]

    def __init__(
        self,
        image_name: Optional[str] = None,
        image_tag: Optional[str] = None,
        timeout: Optional[int] = None,
        use_docker: bool = True,
        config: Optional[Config] = None,
    ):
        """
        Args:
            image_name: Override the Docker image name.
            image_tag: Override the Docker image tag.
            timeout: Per-scan timeout in seconds (Docker mode only; local
                mode is bounded by network + analyzer timeouts).
            use_docker: When ``False`` skip the container entirely and run
                in-process. Intended for SDK users on shared CI runners or
                where Docker isn't available. Local mode never executes
                package code, rejects HTTP URLs and bounds archive size —
                see :mod:`mcpscanner.core.package_sandbox`.
            config: Optional pre-built ``Config``. Only used in local mode.
                When omitted the scanner builds one from the standard
                ``MCP_SCANNER_LLM_*`` environment variables.
        """
        profile = self.PROFILE
        self._image_name = image_name or profile.default_image_name
        self._image_tag = image_tag or default_scanner_image_tag(ecosystem=profile.name)
        self._timeout = timeout or profile.default_timeout
        self._full_image = f"{self._image_name}:{self._image_tag}"
        self._use_docker = use_docker
        self._config = config

    # ------------------------------------------------------------------
    # Docker plumbing
    # ------------------------------------------------------------------

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
                f"Docker is not installed. {self.PROFILE.docker_missing_hint}"
            )
        except subprocess.TimeoutExpired:
            raise DockerNotAvailableError(
                "Docker did not respond within 10 seconds."
                f"{self.PROFILE.docker_unresponsive_hint}"
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
            logger.info(
                "Docker image %s already exists, skipping build", self._full_image
            )
            return

        logger.info("Building Docker image %s ...", self._full_image)

        try:
            context, dockerfile, build_args = prepare_docker_build(
                dockerfile=self.PROFILE.dockerfile
            )
        except DockerBuildError as exc:
            raise self.PROFILE.scan_error(str(exc)) from exc

        cmd = [
            "docker",
            "build",
            "-t",
            self._full_image,
            "-f",
            str(dockerfile),
        ]
        for key, value in build_args.items():
            cmd.extend(["--build-arg", f"{key}={value}"])
        cmd.append(str(context))

        logger.debug("Running: %s", redact_argv_for_logging(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode != 0:
            raise self.PROFILE.scan_error(
                f"Failed to build {self.PROFILE.build_failure_subject}:"
                f"\n{result.stderr.strip()}"
            )

        logger.info("Docker image %s built successfully", self._full_image)

    # ------------------------------------------------------------------
    # Public entrypoints
    # ------------------------------------------------------------------

    def scan_package(
        self,
        package: str,
        version: Optional[str] = None,
        verbose: bool = False,
    ) -> dict:
        """Scan a package (synchronous).

        Args:
            package: Package name as published to the registry.
            version: Specific version to scan (default: latest).
            verbose: Print container stderr to host stderr (Docker mode).

        Returns:
            Dictionary with scan results.

        Raises:
            DockerNotAvailableError: If Docker is required but unavailable.
            LLMNotConfiguredError: In local mode when no LLM key is set.
            RuntimeError: If called from inside an already-running event
                loop; use :meth:`scan_package_async` instead.
            Exception: The ecosystem's own scan error on failure.
        """
        if self._use_docker:
            self._validate_package(package)
            return self._scan_in_docker(package, version, verbose)
        assert_loop_not_running(f"{type(self).__name__}.scan_package")
        self._validate_package(package)
        return asyncio.run(self._scan_locally(package, version))

    async def scan_package_async(
        self,
        package: str,
        version: Optional[str] = None,
        verbose: bool = False,
    ) -> dict:
        """Async-friendly counterpart of :meth:`scan_package`.

        SDK consumers running inside an event loop (FastAPI handlers,
        notebooks, etc.) must use this entrypoint so the analyzer's own
        ``async def`` calls compose with their loop. Docker mode shells out
        via ``subprocess.run``; that runs on the default executor so the
        calling loop isn't blocked for the duration of the container scan.
        """
        if self._use_docker:
            self._validate_package(package)
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, self._scan_in_docker, package, version, verbose
            )
        self._validate_package(package)
        return await self._scan_locally(package, version)

    # ------------------------------------------------------------------
    # Ecosystem-specific steps
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_package(package: str) -> None:
        """Reject names the registry would not accept, before any I/O."""
        raise NotImplementedError

    def _scan_in_docker(
        self, package: str, version: Optional[str], verbose: bool
    ) -> dict:
        """Run the scan inside the hardened container."""
        raise NotImplementedError

    async def _scan_locally(self, package: str, version: Optional[str]) -> dict:
        """Run the scan in-process, without executing package code."""
        raise NotImplementedError
