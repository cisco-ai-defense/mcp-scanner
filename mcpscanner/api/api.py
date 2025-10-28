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
from fastapi import FastAPI, HTTPException

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

# AWS Bedrock configuration
AWS_REGION = os.environ.get(CONSTANTS.ENV_AWS_REGION, CONSTANTS.DEFAULT_AWS_REGION)
AWS_SESSION_TOKEN = os.environ.get(CONSTANTS.ENV_AWS_SESSION_TOKEN, "")
AWS_PROFILE = os.environ.get(CONSTANTS.ENV_AWS_PROFILE, "")

app = FastAPI(
    title="MCP Scanner SDK API",
    description="An API to scan MCP server tools for security findings using both Cisco AI Defense and custom YARA rules.",
    version="1.0.0",
)


def _validate_api_config(
    api_scan: bool,
    api_key: str,
    llm_scan: bool,
    llm_api_key: str,
    llm_model: str,
    aws_region: str,
    aws_profile: str,
) -> None:
    """Validate API configuration when API scan is requested.

    Args:
        api_scan (bool): Whether API scan is requested.
        api_key (str): The API key to validate.
        llm_scan (bool): Whether LLM scan is requested.
        llm_api_key (str): The LLM API key to validate.
        llm_model (str): The LLM model to use.
        aws_region (str): AWS region for Bedrock.
        aws_profile (str): AWS profile for Bedrock.

    Raises:
        HTTPException: If API scan is requested but config is invalid.
    """
    if api_scan and not api_key:
        raise HTTPException(
            status_code=400,
            detail=f"API analyzer requested but configuration is missing. Please set {CONSTANTS.ENV_API_KEY} environment variable.",
        )

    if llm_scan:
        # Check if it's a Bedrock model
        is_bedrock = llm_model and "bedrock/" in llm_model

        if is_bedrock:
            # For Bedrock: Either API key OR AWS credentials (region/profile) must be configured
            has_api_key = bool(llm_api_key)
            has_aws_credentials = bool(aws_profile)

            if not has_api_key and not has_aws_credentials:
                raise HTTPException(
                    status_code=400,
                    detail=f"LLM analyzer with Bedrock model requested but configuration is missing. "
                           f"Please set either {CONSTANTS.ENV_LLM_API_KEY} (for Bedrock API key) "
                           f"or AWS credentials ({CONSTANTS.ENV_AWS_REGION}, {CONSTANTS.ENV_AWS_PROFILE}) environment variables.",
                )
        else:
            # For non-Bedrock models: API key is required
            if not llm_api_key:
                raise HTTPException(
                    status_code=400,
                    detail=f"LLM analyzer requested but configuration is missing. Please set {CONSTANTS.ENV_LLM_API_KEY} environment variable.",
                )


def _prepare_scanner_config(analyzers: List[AnalyzerEnum]) -> tuple[str, str, str, str, str, str]:
    """Prepare scanner configuration based on scan requirements.

    Args:
        analyzers (List[AnalyzerEnum]): List of analyzers to run.

    Returns:
        tuple[str, str, str, str, str, str]: The API key, endpoint URL, LLM API key, AWS region, AWS session token, and AWS profile to use.

    Raises:
        HTTPException: If API scan is requested but config is invalid.
    """
    api_scan = AnalyzerEnum.API in analyzers
    llm_scan = AnalyzerEnum.LLM in analyzers

    api_key_to_use = API_KEY
    llm_api_key_to_use = LLM_API_KEY
    endpoint_url = ENDPOINT_URL
    aws_region_to_use = AWS_REGION
    aws_session_token_to_use = AWS_SESSION_TOKEN
    aws_profile_to_use = AWS_PROFILE

    # Validate configuration if API scan or LLM scan is requested
    _validate_api_config(api_scan, api_key_to_use, llm_scan, llm_api_key_to_use, LLM_MODEL, aws_region_to_use, aws_profile_to_use)

    # If not doing API scan, we don't need an API key
    if not api_scan:
        api_key_to_use = ""

    # If not doing LLM scan, we don't need LLM-related configuration
    if not llm_scan:
        llm_api_key_to_use = ""
        aws_region_to_use = ""
        aws_session_token_to_use = ""
        aws_profile_to_use = ""

    return api_key_to_use, endpoint_url, llm_api_key_to_use, aws_region_to_use, aws_session_token_to_use, aws_profile_to_use


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
        api_key, endpoint_url, llm_api_key, aws_region, aws_session_token, aws_profile = _prepare_scanner_config(analyzers)
        config = Config(
            api_key=api_key,
            endpoint_url=endpoint_url,
            llm_provider_api_key=llm_api_key,
            llm_model=LLM_MODEL,
            aws_region_name=aws_region,
            aws_session_token=aws_session_token,
            aws_profile_name=aws_profile,
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
