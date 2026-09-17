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

"""Config and auth construction from CLI arguments."""

import os
from typing import Dict, List, Optional

from mcpscanner import Config
from mcpscanner.core.auth import Auth
from mcpscanner.core.models import AnalyzerEnum


def _get_endpoint_from_env() -> str:
    return os.environ.get("MCP_SCANNER_ENDPOINT", "")


def _parse_custom_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    """Parse custom headers from CLI arguments.

    Args:
        header_list: List of header strings in 'Name: Value' format.

    Returns:
        Dictionary of header name to value mappings.

    Raises:
        ValueError: If a header string is not in valid format.
    """
    if not header_list:
        return {}

    headers = {}
    for header_str in header_list:
        if ":" not in header_str:
            raise ValueError(
                f"Invalid header format: '{header_str}'. Use 'Name: Value' format."
            )
        # Split on first colon only to handle values containing colons (e.g., URLs)
        name, value = header_str.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def _create_auth_with_headers(
    bearer_token: Optional[str],
    custom_headers: Dict[str, str],
) -> Optional[Auth]:
    """Create Auth object with bearer token and/or custom headers.

    Args:
        bearer_token: Optional bearer token for authentication.
        custom_headers: Dictionary of custom headers.

    Returns:
        Auth object if any authentication is configured, None otherwise.
    """
    if not bearer_token and not custom_headers:
        return None

    if bearer_token and custom_headers:
        # Both bearer token and custom headers
        auth = Auth.bearer(bearer_token)
        auth.custom_headers = custom_headers
        return auth
    elif bearer_token:
        # Only bearer token
        return Auth.bearer(bearer_token)
    else:
        # Only custom headers
        return Auth.custom(custom_headers)


def _build_config(
    selected_analyzers: List[AnalyzerEnum], endpoint_url: Optional[str] = None
) -> Config:
    api_key = os.environ.get("MCP_SCANNER_API_KEY", "")
    llm_api_key = os.environ.get("MCP_SCANNER_LLM_API_KEY", "")
    llm_base_url = os.environ.get("MCP_SCANNER_LLM_BASE_URL")
    llm_api_version = os.environ.get("MCP_SCANNER_LLM_API_VERSION")
    llm_model = os.environ.get("MCP_SCANNER_LLM_MODEL")
    llm_timeout = os.environ.get("MCP_SCANNER_LLM_TIMEOUT")
    stdio_timeout = os.environ.get("MCP_SCANNER_STDIO_TIMEOUT")
    endpoint_url = endpoint_url or _get_endpoint_from_env()

    config_params = {
        "api_key": api_key if AnalyzerEnum.API in selected_analyzers else "",
        "endpoint_url": endpoint_url,
        "llm_provider_api_key": (
            llm_api_key
            if (
                AnalyzerEnum.LLM in selected_analyzers
                or AnalyzerEnum.BEHAVIORAL in selected_analyzers
                or AnalyzerEnum.META in selected_analyzers
            )
            else ""
        ),
        "llm_model": (
            llm_model
            if (
                AnalyzerEnum.LLM in selected_analyzers
                or AnalyzerEnum.BEHAVIORAL in selected_analyzers
                or AnalyzerEnum.META in selected_analyzers
            )
            else ""
        ),
    }

    if llm_base_url:
        config_params["llm_base_url"] = llm_base_url
    if llm_api_version:
        config_params["llm_api_version"] = llm_api_version
    if llm_timeout:
        config_params["llm_timeout"] = float(llm_timeout)
    if stdio_timeout:
        config_params["stdio_timeout"] = int(stdio_timeout)

    # VirusTotal configuration — pass API key so Config can wire it up;
    # remaining VT settings (max_files, extensions, etc.) fall back to
    # constants / env vars inside Config.__init__.
    if AnalyzerEnum.VIRUSTOTAL in selected_analyzers:
        vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if vt_api_key:
            config_params["virustotal_api_key"] = vt_api_key
        vt_upload = os.environ.get("MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES", "").lower()
        if vt_upload == "true":
            config_params["virustotal_upload_files"] = True

    return Config(**config_params)
