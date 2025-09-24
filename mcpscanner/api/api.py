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

"""API module for MCP Scanner SDK.

This module provides a FastAPI application for scanning MCP servers and tools.
"""

import os
from typing import List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI

from ..config.config import Config
from ..config.constants import CONSTANTS
from ..core.models import AnalyzerEnum
from ..core.scanner import Scanner, ScannerFactory
from .router import get_scanner, router as api_router

load_dotenv()
API_KEY = os.environ.get(CONSTANTS.ENV_API_KEY, "")
ENDPOINT_URL = os.environ.get(CONSTANTS.ENV_ENDPOINT, CONSTANTS.API_BASE_URL)
LLM_API_KEY = os.environ.get(CONSTANTS.ENV_LLM_API_KEY, "")
LLM_MODEL = os.environ.get(CONSTANTS.ENV_LLM_MODEL, CONSTANTS.DEFAULT_LLM_MODEL)

app = FastAPI(
    title="MCP Scanner SDK API",
    description="An API to scan MCP server tools for vulnerabilities using both Cisco AI Defense and custom YARA rules.",
    version="1.0.0",
)


def _validate_api_config(
    api_scan: bool,
    api_key: str,
    llm_scan: bool,
    llm_api_key: str,
) -> None:
    """Validate API configuration when API scan is requested.

    Args:
        api_scan (bool): Whether API scan is requested.
        api_key (str): The API key to validate.
        llm_scan (bool): Whether LLM scan is requested.
        llm_api_key (str): The LLM API key to validate.

    Raises:
        HTTPException: If API scan is requested but config is invalid.
    """
    if api_scan and not api_key:
        raise HTTPException(
            status_code=400,
            detail=f"API analyzer requested but configuration is missing. Please set {CONSTANTS.ENV_API_KEY} environment variable.",
        )

    if llm_scan and not llm_api_key:
        raise HTTPException(
            status_code=400,
            detail=f"LLM analyzer requested but configuration is missing. Please set {CONSTANTS.ENV_LLM_API_KEY} environment variable.",
        )


def _prepare_scanner_config(analyzers: List[AnalyzerEnum]) -> tuple[str, str, str]:
    """Prepare scanner configuration based on scan requirements.

    Args:
        analyzers (List[AnalyzerEnum]): List of analyzers to run.

    Returns:
        tuple[str, str, str]: The API key, endpoint URL, and LLM API key to use.

    Raises:
        HTTPException: If API scan is requested but config is invalid.
    """
    api_scan = AnalyzerEnum.API in analyzers
    llm_scan = AnalyzerEnum.LLM in analyzers

    api_key_to_use = API_KEY
    llm_api_key_to_use = LLM_API_KEY
    endpoint_url = ENDPOINT_URL

    # Validate configuration if API scan or LLM scan is requested
    _validate_api_config(api_scan, api_key_to_use, llm_scan, llm_api_key_to_use)

    # If not doing API scan, we don't need an API key
    if not api_scan:
        api_key_to_use = ""

    # If not doing LLM scan, we don't need an LLM API key
    if not llm_scan:
        llm_api_key_to_use = ""

    return api_key_to_use, endpoint_url, llm_api_key_to_use


def create_default_scanner_factory() -> ScannerFactory:
    """Create a factory for the default scanner.

    Returns:
        ScannerFactory: A function that takes analyzers and returns a Scanner instance.
    """

    def scanner_factory(
        analyzers: List[AnalyzerEnum], rules_path: Optional[str] = None
    ) -> Scanner:
        """Create a default scanner instance with configuration from environment variables.
        Args:
            analyzers: List of analyzers to run.
            rules_path (Optional[str]): Custom path to YARA rules directory.

        Returns:
            Scanner: A configured scanner instance.

        Raises:
            HTTPException: If API scan is requested but config is invalid.
        """
        api_key, endpoint_url, llm_api_key = _prepare_scanner_config(analyzers)
        config = Config(
            api_key=api_key,
            endpoint_url=endpoint_url,
            llm_provider_api_key=llm_api_key,
            llm_model=LLM_MODEL,
        )
        return Scanner(config, rules_dir=rules_path)

    return scanner_factory


# Include the reusable router
app.include_router(api_router)

# Provide the dependency override for the default scanner
app.dependency_overrides[get_scanner] = create_default_scanner_factory


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}
