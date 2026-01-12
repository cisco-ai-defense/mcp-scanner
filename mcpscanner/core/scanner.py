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

"""Scanner module for MCP Scanner SDK.

This module contains the unified scanner class that combines API and YARA analyzers.
"""

import asyncio
import json
import logging as stdlib_logging
import warnings
from typing import Any, Dict, List, Optional, Tuple, Callable
import httpx
import os
import shlex
import shutil

# MCP client imports
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Tool as MCPTool, Prompt as MCPPrompt
from mcp import StdioServerParameters
try:
    from mcp.shared.exceptions import McpError
except ImportError:  # pragma: no cover - fallback for environments without mcp installed
    class McpError(Exception):
        """Fallback error class when MCP dependency is unavailable."""
        pass

from ..config.config import Config
from ..utils.logging_config import get_logger
from ..utils.command_utils import (
    build_env_for_expansion,
    decide_windows_semantics,
    expand_text,
    normalize_and_expand_command_args,
    split_embedded_args,
    resolve_executable_path,
)
from .analyzers.api_analyzer import ApiAnalyzer
from .analyzers.base import BaseAnalyzer
from .analyzers.llm_analyzer import LLMAnalyzer
from .analyzers.yara_analyzer import YaraAnalyzer
from .analyzers.behavioral import BehavioralCodeAnalyzer
from .auth import (
    Auth,
    AuthType,
    create_oauth_provider_from_auth,
)
from .exceptions import (
    MCPConnectionError,
    MCPAuthenticationError,
    MCPServerNotFoundError,
)
from .models import AnalyzerEnum
from .mcp_models import StdioServer, RemoteServer
from ..config.config_parser import MCPConfigScanner
from .result import ScanResult, ToolScanResult, PromptScanResult, ResourceScanResult, InstructionsScanResult

ScannerFactory = Callable[[List[AnalyzerEnum], Optional[str]], "Scanner"]

logger = get_logger(__name__)


class Scanner:
    """Unified scanner class that combines API and YARA analyzers.

    This class provides a comprehensive scanning solution by combining
    API-based analysis and YARA pattern matching. It can connect to MCP servers
    to scan tools directly.

    Example:
        >>> from mcpscanner import Config, Scanner
        >>> config = Config(api_key="your_api_key", endpoint_url="https://eu.api.inspect.aidefense.security.cisco.com/api/v1")
        >>> scanner = Scanner(config)
        >>> # Scan a specific tool on a remote server
        >>> result = await scanner.scan_remote_server_tool("https://mcp-server.example.com", "tool_name")
        >>> # Or scan all tools on a remote server
        >>> results = await scanner.scan_remote_server_tools("https://mcp-server.example.com")
        >>> # You can also analyze content directly without connecting to a server
        >>> result = await scanner.analyze(name="tool_name", description="tool description")
    """

    DEFAULT_ANALYZERS = [AnalyzerEnum.API, AnalyzerEnum.YARA]

    def __init__(
        self,
        config: Config,
        rules_dir: Optional[str] = None,
        custom_analyzers: Optional[List[BaseAnalyzer]] = None,
    ):
        """Initialize a new Scanner instance.

        Args:
            config (Config): The configuration for the scanner.
            rules_dir (Optional[str]): Custom path to YARA rules directory.
            custom_analyzers (Optional[List[BaseAnalyzer]]): A list of custom analyzer instances.
        """
        self._config = config
        self._api_analyzer = ApiAnalyzer(config) if config.api_key else None
        self._yara_analyzer = YaraAnalyzer(rules_dir=rules_dir)

        # LLM analyzer can be used with either API key or Bedrock (AWS credentials)
        is_bedrock = config.llm_model and "bedrock/" in config.llm_model
        self._llm_analyzer = (
            LLMAnalyzer(config) if (config.llm_provider_api_key or is_bedrock) else None
        )
        self._behavioral_analyzer = (
            BehavioralCodeAnalyzer(config) if config.llm_provider_api_key else None
        )
        self._custom_analyzers = custom_analyzers or []

        # Debug logging for analyzer initialization
        active_analyzers = []
        if self._api_analyzer:
            active_analyzers.append("API")
        if self._yara_analyzer:
            active_analyzers.append("YARA")
        if self._llm_analyzer:
            active_analyzers.append("LLM")
        if self._behavioral_analyzer:
            active_analyzers.append("Behavioral")
        for analyzer in self._custom_analyzers:
            active_analyzers.append(f"{analyzer.name}")
        logger.debug(f'Scanner initialized: active_analyzers="{active_analyzers}"')

    def get_custom_analyzers(self) -> List[BaseAnalyzer]:
        """Get the list of custom analyzers used by the scanner.
        Returns:
            List[BaseAnalyzer]: List of custom analyzers.
        """
        return self._custom_analyzers

    def _validate_analyzer_requirements(
        self, requested_analyzers: List[AnalyzerEnum]
    ) -> None:
        """Validate that all requested analyzers have the required configuration.

        Args:
            requested_analyzers (List[AnalyzerEnum]): List of analyzers that were requested.

        Raises:
            ValueError: If a requested analyzer cannot be used due to missing configuration.
        """
        missing_requirements = []

        if AnalyzerEnum.API in requested_analyzers and not self._api_analyzer:
            missing_requirements.append(
                "API analyzer requested but MCP_SCANNER_API_KEY not configured"
            )

        if AnalyzerEnum.LLM in requested_analyzers and not self._llm_analyzer:
            missing_requirements.append(
                "LLM analyzer requested but MCP_SCANNER_LLM_API_KEY not configured (or AWS credentials for Bedrock models)"
            )

        if AnalyzerEnum.BEHAVIORAL in requested_analyzers and not self._behavioral_analyzer:
            missing_requirements.append(
                "Behavioral analyzer requested but MCP_SCANNER_LLM_API_KEY not configured"
            )

        # YARA analyzer should always be available since it doesn't require API keys
        if AnalyzerEnum.YARA in requested_analyzers and not self._yara_analyzer:
            missing_requirements.append(
                "YARA analyzer requested but failed to initialize"
            )

        if missing_requirements:
            error_msg = (
                "Cannot proceed with scan - missing required configuration:\n"
                + "\n".join(f"  • {req}" for req in missing_requirements)
            )
            raise ValueError(error_msg)

    @staticmethod
    def _is_missing_capability_error(error: Exception) -> bool:
        """Return True when the server reports a capability is unavailable."""
        messages = [str(error)]
        code = getattr(error, "code", None)

        rpc_error = getattr(error, "error", None)
        if hasattr(rpc_error, "code") and getattr(rpc_error, "code") is not None:
            code = code or rpc_error.code
            rpc_message = getattr(rpc_error, "message", None)
            if rpc_message:
                messages.append(str(rpc_message))
        elif isinstance(rpc_error, dict):
            code = code or rpc_error.get("code")
            rpc_message = rpc_error.get("message")
            if rpc_message:
                messages.append(str(rpc_message))

        combined_message = " ".join(m for m in messages if m).lower()

        if code == -32601:
            return True

        tokens = (
            "method not found",
            "methodnotfound",
            "not implemented",
            "unsupported",
            "does not have",
            "doesn't have",
        )
        return any(token in combined_message for token in tokens)

    async def _analyze_tool(
        self,
        tool: MCPTool,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> ToolScanResult:
        """Analyze a single MCP tool using specified analyzers.

        Args:
            tool (MCPTool): The MCP tool to analyze.
            analyzers (List[AnalyzerEnum]): List of analyzers to run.

        Returns:
            ScanResult: The result of the analysis.
        """
        all_findings = []
        name = tool.name
        description = tool.description
        tool_json = tool.model_dump_json()
        tool_data = json.loads(tool_json)

        if AnalyzerEnum.API in analyzers and self._api_analyzer:
            # Run API analysis on the description
            try:
                api_context = {"tool_name": name, "content_type": "description"}
                api_findings = await self._api_analyzer.analyze(
                    description, api_context
                )
                for finding in api_findings:
                    finding.analyzer = "API"
                all_findings.extend(api_findings)
            except Exception as e:
                logger.error(
                    f'API analysis failed on description: tool="{name}", error="{e}"'
                )

        if AnalyzerEnum.YARA in analyzers:
            # Run YARA analysis on the description
            try:
                yara_desc_context = {"tool_name": name, "content_type": "description"}
                yara_desc_findings = await self._yara_analyzer.analyze(
                    description, yara_desc_context
                )
                for finding in yara_desc_findings:
                    finding.analyzer = "YARA"
                all_findings.extend(yara_desc_findings)
            except Exception as e:
                logger.error(
                    f'YARA analysis failed on description: tool="{name}", error="{e}"'
                )

            # Run YARA analysis on the tool parameters
            try:
                # Remove description from the JSON as it is already analyzed
                if "description" in tool_data:
                    del tool_data["description"]
                tool_json_str = json.dumps(tool_data)
                yara_params_context = {"tool_name": name, "content_type": "parameters"}
                yara_params_findings = await self._yara_analyzer.analyze(
                    tool_json_str, yara_params_context
                )
                for finding in yara_params_findings:
                    finding.analyzer = "YARA"
                all_findings.extend(yara_params_findings)
            except Exception as e:
                logger.error(
                    f'YARA analysis failed on parameters: tool="{name}", error="{e}"'
                )

        if AnalyzerEnum.LLM in analyzers and self._llm_analyzer:
            # Run LLM analysis on the complete tool information
            try:
                # Format content for comprehensive analysis
                analysis_content = f"Tool Name: {name}\n"
                analysis_content += f"Description: {description}\n"
                if "inputSchema" in tool_data:
                    analysis_content += f"Parameters Schema: {json.dumps(tool_data['inputSchema'], indent=2)}\n"

                llm_context = {"tool_name": name, "content_type": "comprehensive"}
                llm_findings = await self._llm_analyzer.analyze(
                    analysis_content, llm_context
                )
                for finding in llm_findings:
                    finding.analyzer = "LLM"
                all_findings.extend(llm_findings)
            except Exception as e:
                logger.error(f'LLM analysis failed: tool="{name}", error="{e}"')
        elif AnalyzerEnum.LLM in analyzers and not self._llm_analyzer:
            logger.warning(
                f"LLM scan requested for tool \"'{name}'\" but LLM analyzer not initialized (MCP_SCANNER_LLM_API_KEY missing)"
            )

        # Run custom analyzers
        custom_analyzer_names = []
        for analyzer in self._custom_analyzers:
            try:
                custom_context = {"tool_name": name, "content_type": "description"}
                # Add HTTP headers to context for custom analyzers
                if http_headers:
                    custom_context["http_headers"] = http_headers
                findings = await analyzer.analyze(description, custom_context)
                for finding in findings:
                    finding.analyzer = analyzer.name
                all_findings.extend(findings)
                # Track which custom analyzers were successfully run
                custom_analyzer_names.append(analyzer.name)
            except Exception as e:
                logger.error(
                    f'Custom analyzer "{analyzer.name}" failed: tool="{name}", error="{e}"'
                )

        # Combine enum analyzers and custom analyzer names
        all_analyzers = list(analyzers) + custom_analyzer_names

        return ToolScanResult(
            tool_name=name,
            tool_description=description,
            status="completed",
            analyzers=all_analyzers,
            findings=all_findings,
        )

    async def _analyze_prompt(
        self,
        prompt: MCPPrompt,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> PromptScanResult:
        """Analyze a single MCP prompt using specified analyzers.

        Args:
            prompt (MCPPrompt): The MCP prompt to analyze.
            analyzers (List[AnalyzerEnum]): List of analyzers to run.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            PromptScanResult: The result of the analysis.
        """
        all_findings = []
        name = prompt.name
        description = prompt.description or ""

        # Safely parse prompt data
        try:
            prompt_json = prompt.model_dump_json()
            prompt_data = json.loads(prompt_json)
        except (json.JSONDecodeError, AttributeError, TypeError) as e:
            logger.warning(f"Error parsing prompt '{name}' data: {e}. Using minimal data.")
            prompt_data = {"name": name, "description": description}

        if AnalyzerEnum.API in analyzers and self._api_analyzer:
            # Run API analysis on the description
            try:
                api_context = {"prompt_name": name, "content_type": "description"}
                api_findings = await self._api_analyzer.analyze(
                    description, api_context
                )
                for finding in api_findings:
                    finding.analyzer = "API"
                all_findings.extend(api_findings)
            except Exception as e:
                logger.error(
                    f'API analysis failed on prompt description: prompt="{name}", error="{e}"'
                )

        if AnalyzerEnum.YARA in analyzers:
            # Run YARA analysis on the description
            try:
                yara_desc_context = {"prompt_name": name, "content_type": "description"}
                yara_desc_findings = await self._yara_analyzer.analyze(
                    description, yara_desc_context
                )
                for finding in yara_desc_findings:
                    finding.analyzer = "YARA"
                all_findings.extend(yara_desc_findings)
            except Exception as e:
                logger.error(
                    f'YARA analysis failed on prompt description: prompt="{name}", error="{e}"'
                )

            # Run YARA analysis on the prompt arguments/structure
            try:
                # Remove description from the JSON as it is already analyzed
                if "description" in prompt_data:
                    del prompt_data["description"]
                prompt_json_str = json.dumps(prompt_data)
                yara_params_context = {"prompt_name": name, "content_type": "arguments"}
                yara_params_findings = await self._yara_analyzer.analyze(
                    prompt_json_str, yara_params_context
                )
                for finding in yara_params_findings:
                    finding.analyzer = "YARA"
                all_findings.extend(yara_params_findings)
            except Exception as e:
                logger.error(
                    f'YARA analysis failed on prompt arguments: prompt="{name}", error="{e}"'
                )

        if AnalyzerEnum.LLM in analyzers and self._llm_analyzer:
            # Run LLM analysis on the complete prompt information
            try:
                # Format content for comprehensive analysis
                analysis_content = f"Prompt Name: {name}\n"
                analysis_content += f"Description: {description}\n"
                if "arguments" in prompt_data and prompt_data["arguments"]:
                    analysis_content += f"Arguments: {json.dumps(prompt_data['arguments'], indent=2)}\n"

                llm_context = {"prompt_name": name, "content_type": "comprehensive"}
                llm_findings = await self._llm_analyzer.analyze(
                    analysis_content, llm_context
                )
                for finding in llm_findings:
                    finding.analyzer = "LLM"
                all_findings.extend(llm_findings)
            except Exception as e:
                logger.error(f'LLM analysis failed: prompt="{name}", error="{e}"')
        elif AnalyzerEnum.LLM in analyzers and not self._llm_analyzer:
            logger.warning(
                f"LLM scan requested for prompt '{name}' but LLM analyzer not initialized (MCP_SCANNER_LLM_API_KEY missing)"
            )

        # Run custom analyzers
        custom_analyzer_names = []
        for analyzer in self._custom_analyzers:
            try:
                custom_context = {"prompt_name": name, "content_type": "description"}
                # Add HTTP headers to context for custom analyzers
                if http_headers:
                    custom_context["http_headers"] = http_headers
                findings = await analyzer.analyze(description, custom_context)
                for finding in findings:
                    finding.analyzer = analyzer.name
                all_findings.extend(findings)
                # Track which custom analyzers were successfully run
                custom_analyzer_names.append(analyzer.name)
            except Exception as e:
                logger.error(
                    f'Custom analyzer "{analyzer.name}" failed: prompt="{name}", error="{e}"'
                )

        # Combine enum analyzers and custom analyzer names
        all_analyzers = list(analyzers) + custom_analyzer_names

        return PromptScanResult(
            prompt_name=name,
            prompt_description=description,
            status="completed",
            analyzers=all_analyzers,
            findings=all_findings,
        )

    async def _analyze_instructions(
        self,
        instructions: str,
        server_name: str,
        protocol_version: str,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> InstructionsScanResult:
        """Analyze server instructions using specified analyzers.

        Args:
            instructions (str): The instructions text from the server.
            server_name (str): The name of the server.
            protocol_version (str): The MCP protocol version.
            analyzers (List[AnalyzerEnum]): List of analyzers to run.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            InstructionsScanResult: The result of the analysis.
        """
        all_findings = []

        if AnalyzerEnum.API in analyzers and self._api_analyzer:
            # Run API analysis on the instructions
            try:
                api_context = {"server_name": server_name, "content_type": "instructions"}
                api_findings = await self._api_analyzer.analyze(
                    instructions, api_context
                )
                for finding in api_findings:
                    finding.analyzer = "API"
                all_findings.extend(api_findings)
            except Exception as e:
                logger.error(
                    f'API analysis failed on instructions: server="{server_name}", error="{e}"'
                )

        if AnalyzerEnum.YARA in analyzers:
            # Run YARA analysis on the instructions
            try:
                yara_context = {"server_name": server_name, "content_type": "instructions"}
                yara_findings = await self._yara_analyzer.analyze(
                    instructions, yara_context
                )
                for finding in yara_findings:
                    finding.analyzer = "YARA"
                all_findings.extend(yara_findings)
            except Exception as e:
                logger.error(
                    f'YARA analysis failed on instructions: server="{server_name}", error="{e}"'
                )

        if AnalyzerEnum.LLM in analyzers and self._llm_analyzer:
            # Run LLM analysis on the instructions
            try:
                # Format content for comprehensive analysis
                analysis_content = f"Server Name: {server_name}\n"
                analysis_content += f"Protocol Version: {protocol_version}\n"
                analysis_content += f"Instructions: {instructions}\n"

                llm_context = {"server_name": server_name, "content_type": "instructions"}
                llm_findings = await self._llm_analyzer.analyze(
                    analysis_content, llm_context
                )
                for finding in llm_findings:
                    finding.analyzer = "LLM"
                all_findings.extend(llm_findings)
            except Exception as e:
                logger.error(f'LLM analysis failed on instructions: server="{server_name}", error="{e}"')
        elif AnalyzerEnum.LLM in analyzers and not self._llm_analyzer:
            logger.warning(
                f"LLM scan requested for instructions from '{server_name}' but LLM analyzer not initialized (MCP_SCANNER_LLM_API_KEY missing)"
            )

        # Run custom analyzers
        custom_analyzer_names = []
        for analyzer in self._custom_analyzers:
            try:
                custom_context = {"server_name": server_name, "content_type": "instructions"}
                # Add HTTP headers to context for custom analyzers
                if http_headers:
                    custom_context["http_headers"] = http_headers
                findings = await analyzer.analyze(instructions, custom_context)
                for finding in findings:
                    finding.analyzer = analyzer.name
                all_findings.extend(findings)
                # Track which custom analyzers were successfully run
                custom_analyzer_names.append(analyzer.name)
            except Exception as e:
                logger.error(
                    f'Custom analyzer "{analyzer.name}" failed on instructions: server="{server_name}", error="{e}"'
                )

        # Combine enum analyzers and custom analyzer names
        all_analyzers = list(analyzers) + custom_analyzer_names

        return InstructionsScanResult(
            instructions=instructions,
            server_name=server_name,
            protocol_version=protocol_version,
            status="completed",
            analyzers=all_analyzers,
            findings=all_findings,
        )

    def _check_http_error_in_logs(self, msg: str) -> Optional[int]:
        """Check if a log message contains an HTTP error status code.

        Args:
            msg: Log message to check

        Returns:
            HTTP status code if found (401, 403, 404), None otherwise
        """
        if "401" in msg or "Unauthorized" in msg:
            return 401
        elif "403" in msg or "Forbidden" in msg:
            return 403
        elif "404" in msg or "Not Found" in msg:
            return 404
        return None

    async def _close_mcp_session(self, client_context, session):
        """Close MCP session and client context safely.

        Args:
            client_context: The MCP client context
            session: The MCP session
        """
        # Close session first
        if session:
            try:
                await session.__aexit__(None, None, None)
            except (asyncio.CancelledError, GeneratorExit, RuntimeError, BaseExceptionGroup):
                # Suppress cleanup errors from MCP library bugs
                # These are expected when connection fails
                pass
            except Exception as e:
                # Log unexpected errors
                if "cancel scope" not in str(e) and "TaskGroup" not in str(e):
                    logger.warning(f"Error closing session: {e}")

        # Close client context
        if client_context:
            try:
                # Ensure we're in the same task context for cleanup
                await client_context.__aexit__(None, None, None)
            except (asyncio.CancelledError, GeneratorExit, RuntimeError, BaseExceptionGroup):
                # Suppress cleanup errors from MCP library bugs
                # These are expected when connection fails
                pass
            except Exception as e:
                # Log unexpected errors
                if "cancel scope" not in str(e) and "TaskGroup" not in str(e):
                    logger.warning(f"Error closing client context: {e}")

    async def _get_mcp_session(
        self, server_url: str, auth: Optional[Auth] = None
    ) -> Tuple[Any, ClientSession]:
        """Create an MCP client session for the given server URL.

        Args:
            server_url (str): The URL of the MCP server.
            auth (Optional[Auth]): Explicit authentication configuration. If None, connects without auth.

        Returns:
            tuple: A tuple containing (client_context, session)

        Raises:
            ConnectionError: If unable to connect to the MCP server
        """
        oauth_provider = None
        extra_headers: Dict[str, str] = {}

        # Only use authentication if explicitly provided via Auth parameter
        if auth is not None:
            if auth and auth.type == AuthType.OAUTH:
                logger.debug(
                    f'Using explicit OAuth authentication for MCP server: server="{server_url}"'
                )
                oauth_provider = create_oauth_provider_from_auth(auth, server_url)
            elif auth and auth.type == AuthType.BEARER:
                if not getattr(auth, "bearer_token", None):
                    raise ValueError(
                        "Bearer authentication selected but no bearer_token provided"
                    )
                # Prepare Authorization header for bearer token auth
                extra_headers["Authorization"] = f"Bearer {auth.bearer_token}"
                logger.debug(
                    f'Using explicit Bearer authentication for MCP server: server="{server_url}"'
                )
            elif auth and auth.type == AuthType.APIKEY:
                if not getattr(auth, "api_key", None) or not getattr(auth, "api_key_header", None):
                    raise ValueError(
                        "APIKEY authentication selected but no api key or api header value provided"
                    )
                extra_headers[auth.api_key_header] = auth.api_key
                logger.debug(
                    f'Using APIKEY authentication for MCP server: server="{server_url}"'
                )

            # Add any custom headers from Auth object (works with any auth type)
            if hasattr(auth, 'custom_headers') and auth.custom_headers:
                extra_headers.update(auth.custom_headers)
        else:
            logger.debug(
                f'No explicit auth provided, connecting without authentication: server="{server_url}"'
            )

        # Create client context with or without OAuth
        if oauth_provider:
            client_context = (
                sse_client(server_url, auth=oauth_provider)
                if "/sse" in server_url
                else streamablehttp_client(server_url, auth=oauth_provider)
            )
        else:
            logger.debug(
                f'Using standard connection (no auth) for MCP server: server="{server_url}"'
            )
            # Pass bearer Authorization header when requested
            if "/sse" in server_url:
                client_context = (
                    sse_client(server_url, headers=extra_headers)
                    if extra_headers
                    else sse_client(server_url)
                )
            else:
                client_context = (
                    streamablehttp_client(server_url, headers=extra_headers)
                    if extra_headers
                    else streamablehttp_client(server_url)
                )

        client_context_opened = None
        session = None
        http_status_code = None
        capture_handler = None
        httpx_logger = None
        original_httpx_level = None
        original_propagate = None

        # Set up httpx logging capture to detect HTTP errors
        httpx_logger = stdlib_logging.getLogger("httpx")
        original_httpx_level = httpx_logger.level
        original_propagate = httpx_logger.propagate

        class StatusCodeCapture(stdlib_logging.Handler):
            def __init__(self):
                super().__init__(level=stdlib_logging.INFO)

            def emit(self, record):
                nonlocal http_status_code
                # Capture the status code silently (don't propagate to console)
                http_status_code = self._check_http_error_in_logs(record.getMessage()) or http_status_code

        capture_handler = StatusCodeCapture()
        capture_handler._check_http_error_in_logs = self._check_http_error_in_logs

        # Temporarily set httpx logger to INFO to ensure it emits logs we can capture
        # Disable propagation only if we're raising the log level to avoid console output
        httpx_logger.addHandler(capture_handler)
        if httpx_logger.level > stdlib_logging.INFO or httpx_logger.level == stdlib_logging.NOTSET:
            httpx_logger.setLevel(stdlib_logging.INFO)
            httpx_logger.propagate = False  # Prevent console output

        try:
            logger.debug(f'Attempting to connect to MCP server: server="{server_url}"')
            # Suppress async generator warnings from MCP library cleanup bugs
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*async.*generator.*")
                client_context_opened = await client_context.__aenter__()
                streams = client_context_opened
                read, write, *_ = streams
                session = ClientSession(read, write)
                await session.__aenter__()
                logger.debug(f'Initializing MCP session: server="{server_url}"')
                init_result = await session.initialize()
                # Store the initialize result on the session for later access
                session._init_result = init_result
            logger.debug(f'Successfully connected to MCP server: server="{server_url}"')
            return client_context, session
        except (asyncio.CancelledError, GeneratorExit) as e:
            # These exceptions often wrap HTTP errors from the MCP library
            await self._close_mcp_session(client_context, session)

            # Check if we captured an HTTP error status code from logs
            if http_status_code == 401:
                raise MCPAuthenticationError(
                    f"Authentication failed for MCP server at {server_url}. "
                    f"This server requires OAuth or Bearer token authentication. "
                    f"Use --bearer-token <token> or configure OAuth."
                ) from e
            elif http_status_code == 403:
                raise MCPAuthenticationError(
                    f"Access denied to MCP server at {server_url}. "
                    f"Check your authentication credentials."
                ) from e
            elif http_status_code == 404:
                raise MCPServerNotFoundError(
                    f"MCP server endpoint not found at {server_url}. "
                    f"Please verify the URL is correct."
                ) from e

            # Generic cancellation error
            raise MCPConnectionError(
                f"Connection to MCP server at {server_url} was cancelled. "
                f"This may indicate the server is not reachable, not responding, or requires authentication."
            ) from e
        except BaseExceptionGroup as eg:
            # ExceptionGroup from MCP library - check for HTTP errors
            await self._close_mcp_session(client_context, session)

            # Get the first error for inspection
            first_error = eg.exceptions[0] if eg.exceptions else eg
            error_str = str(first_error)

            # Check if we captured an HTTP error status code from logs, or check error string
            detected_code = http_status_code or self._check_http_error_in_logs(error_str)

            if detected_code == 401:
                raise MCPAuthenticationError(
                    f"Authentication failed for MCP server at {server_url}. "
                    f"This server requires OAuth or Bearer token authentication. "
                    f"Use --bearer-token <token> or configure OAuth. "
                    f"Original error: {first_error}"
                ) from eg
            elif detected_code == 403:
                raise MCPAuthenticationError(
                    f"Access denied to MCP server at {server_url}. "
                    f"Check your authentication credentials. "
                    f"Original error: {first_error}"
                ) from eg
            elif detected_code == 404:
                raise MCPServerNotFoundError(
                    f"MCP server endpoint not found at {server_url}. "
                    f"Please verify the URL is correct. "
                    f"Original error: {first_error}"
                ) from eg

            # Generic ExceptionGroup error
            raise MCPConnectionError(
                f"Error connecting to MCP server at {server_url}: {first_error}"
            ) from eg
        except Exception as e:
            # Try to clean up resources on any error
            await self._close_mcp_session(client_context, session)
            # Convert connection errors to more user-friendly messages
            if "ConnectError" in str(type(e)) or "connection" in str(e).lower() or "nodename nor servname" in str(e):
                raise MCPConnectionError(
                    f"Unable to connect to MCP server at {server_url}. "
                    f"Please verify the server is running and accessible. "
                    f"Original error: {e}"
                ) from e
            raise
        finally:
            # Clean up httpx logger handler and restore original settings
            if capture_handler and httpx_logger:
                httpx_logger.removeHandler(capture_handler)
                if original_httpx_level is not None:
                    httpx_logger.setLevel(original_httpx_level)
                if original_propagate is not None:
                    httpx_logger.propagate = original_propagate

    async def scan_remote_server_tool(
        self,
        server_url: str,
        tool_name: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
    ) -> ToolScanResult:
        """Scan a specific tool on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            tool_name (str): The name of the tool to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.

        Returns:
            ToolScanResult: The result of the scan.

        Raises:
            ValueError: If the tool is not found on the server.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = self.DEFAULT_ANALYZERS

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(server_url, auth)

            # List all tools and find the target tool
            try:
                tool_list = await session.list_tools()
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = (
                        f"Server '{server_url}' does not expose tools; cannot scan '{tool_name}'."
                    )
                    logger.warning(message)
                    raise ValueError(message) from e
                raise
            target_tool = next(
                (t for t in tool_list.tools if t.name == tool_name), None
            )

            if not target_tool:
                raise ValueError(
                    f"Tool '{tool_name}' not found on the server at {server_url}"
                )

            # Analyze the tool
            result = await self._analyze_tool(target_tool, analyzers, http_headers)
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning tool \'{tool_name}\' on MCP server: server="{server_url}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def scan_remote_server_tools(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
    ) -> List[ToolScanResult]:
        """Scan all tools on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            List[ToolScanResult]: The results of the scan for each tool.

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the server URL is invalid or empty.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = self.DEFAULT_ANALYZERS

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(server_url, auth)

            # List all tools
            try:
                tool_list = await session.list_tools()
            except McpError as e:
                if self._is_missing_capability_error(e):
                    logger.warning(
                        f"Server '{server_url}' does not expose tools: {e}"
                    )
                    return []
                raise

            # Create analysis tasks for each tool
            scan_tasks = [
                self._analyze_tool(tool, analyzers, http_headers)
                for tool in tool_list.tools
            ]

            # Run all tasks concurrently
            scan_results = await asyncio.gather(*scan_tasks)
            return scan_results

        except Exception as e:
            logger.error(f"Error scanning server {server_url}: {e}")
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def _get_stdio_session(
        self, server_config: StdioServer, timeout: int = 30
    ) -> Tuple[Any, Any]:
        """Get a stdio session for the given server configuration.

        Args:
            server_config: The stdio server configuration
            timeout: Connection timeout in seconds

        Returns:
            Tuple of (client_context, session)
        """
        client_context = None
        session = None

        try:
            logger.debug(f"Creating stdio client for command: {server_config.command}")

            # Normalize and validate command/args to avoid FileNotFoundError ([Errno 2])
            # Expansion mode comes from StdioServer config; default is 'off'
            expand_mode = (server_config.expand_vars or "off").lower()
            logger.debug(f"expand_mode='{expand_mode}' for command: {server_config.command}")
            env_for_expansion = build_env_for_expansion(server_config.env)
            windows_semantics = decide_windows_semantics(expand_mode)

            expanded_command, expanded_args = normalize_and_expand_command_args(
                server_config.command or "", server_config.args or [], env_for_expansion, expand_mode
            )
            cmd_command, cmd_args = split_embedded_args(
                expanded_command, expanded_args, windows_semantics
            )
            resolved_exe = resolve_executable_path(cmd_command)
            if not resolved_exe or not os.path.exists(resolved_exe):
                # Provide a clear, actionable message and fail fast for this server only
                msg = (
                    f"No such file or command: '{server_config.command}'. "
                    f"Resolved path: '{resolved_exe or 'N/A'}'. "
                    f"Tip: use absolute paths or ensure the binary is on PATH."
                )
                logger.warning(msg)
                raise MCPConnectionError(
                    f"Unable to connect to stdio MCP server with command {server_config.command}. "
                    f"Please verify the command is correct and executable."
                )

            # 5) Build parameters with normalized command/args
            # Merge parent process env with server-specific env (server config takes precedence)
            merged_env = {**os.environ, **(server_config.env or {})}
            server_params = StdioServerParameters(
                command=resolved_exe,
                args=cmd_args,
                env=merged_env,
            )

            # Create client context and session with proper error handling
            client_context = stdio_client(server_params)

            # Use asyncio.wait_for for timeout instead of asyncio.timeout
            try:
                client_context_opened = await asyncio.wait_for(
                    client_context.__aenter__(), timeout=timeout
                )
                read, write = client_context_opened

                session = ClientSession(read, write)
                await asyncio.wait_for(session.__aenter__(), timeout=10)
                await asyncio.wait_for(session.initialize(), timeout=10)

            except asyncio.TimeoutError:
                # Clean up on timeout
                if session:
                    try:
                        await session.__aexit__(None, None, None)
                    except:
                        pass
                if client_context:
                    try:
                        await client_context.__aexit__(None, None, None)
                    except:
                        pass
                raise

            logger.debug(
                f"Successfully connected to stdio MCP server: {server_config.command}"
            )
            return client_context, session

        except asyncio.TimeoutError:
            logger.error(
                f"Timeout connecting to stdio server {server_config.command} after {timeout}s"
            )
            raise MCPConnectionError(
                f"Timeout connecting to stdio MCP server with command {server_config.command}. "
                f"Server took longer than {timeout} seconds to start."
            )
        except asyncio.CancelledError:
            logger.error(
                f"Connection cancelled for stdio server {server_config.command}"
            )
            # Clean up resources on cancellation
            if session:
                try:
                    await session.__aexit__(None, None, None)
                except:
                    pass
            if client_context:
                try:
                    await client_context.__aexit__(None, None, None)
                except:
                    pass
            raise MCPConnectionError(
                f"Connection cancelled for stdio MCP server with command {server_config.command}. "
                f"This may indicate the server failed to start properly."
            )
        except Exception as e:
            logger.error(
                f"Error connecting to stdio server {server_config.command}: {e}"
            )
            # Clean up resources on error
            if session:
                try:
                    await session.__aexit__(None, None, None)
                except:
                    pass
            if client_context:
                try:
                    await client_context.__aexit__(None, None, None)
                except:
                    pass
            raise MCPConnectionError(
                f"Unable to connect to stdio MCP server with command {server_config.command}. "
                f"Please verify the command is correct and executable. "
                f"Original error: {e}"
            ) from e

    async def scan_stdio_server_tools(
        self,
        server_config: StdioServer,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
    ) -> List[ToolScanResult]:
        """Scan tools from a stdio MCP server.

        Args:
            server_config: The stdio server configuration
            analyzers: List of analyzers to use
            timeout: Connection timeout in seconds

        Returns:
            List[ToolScanResult]: List of tool scan results
        """
        if timeout is None:
            timeout = 60

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            # Create a new task for the connection to isolate async contexts
            async def connect_and_scan():
                nonlocal client_context, session
                client_context, session = await self._get_stdio_session(
                    server_config, timeout
                )

                # List all tools
                try:
                    tool_list = await session.list_tools()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            f"Stdio server '{server_config.command}' does not expose tools: {e}"
                        )
                        return []
                    raise

                # Create analysis tasks for each tool
                scan_tasks = [
                    self._analyze_tool(tool, analyzers) for tool in tool_list.tools
                ]

                # Run all tasks concurrently
                scan_results = await asyncio.gather(*scan_tasks)
                return scan_results

            # Run the connection and scanning in an isolated task
            return await connect_and_scan()

        except Exception as e:
            logger.error(f"Error scanning stdio server {server_config.command}: {e}")
            raise
        finally:
            # Always clean up resources
            await self._close_mcp_session(client_context, session)

    async def scan_stdio_server_tool(
        self,
        server_config: StdioServer,
        tool_name: str,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
    ) -> ToolScanResult:
        """Scan a specific tool on a stdio MCP server.

        Args:
            server_config (StdioServer): The stdio server configuration.
            tool_name (str): The name of the tool to scan.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.
            timeout (Optional[int]): Timeout for the connection.

        Returns:
            ToolScanResult: The result of the scan.

        Raises:
            ValueError: If the tool is not found on the server.
        """
        if not server_config.command:
            raise ValueError("No command provided in stdio server configuration.")

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_stdio_session(
                server_config, timeout
            )

            # List all tools and find the target tool
            try:
                tool_list = await session.list_tools()
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = (
                        f"Stdio server '{server_config.command}' does not expose tools; cannot scan '{tool_name}'."
                    )
                    logger.warning(message)
                    raise ValueError(message) from e
                raise
            target_tool = next(
                (t for t in tool_list.tools if t.name == tool_name), None
            )

            if not target_tool:
                raise ValueError(
                    f"Tool '{tool_name}' not found on the stdio server with command {server_config.command}"
                )

            # Analyze the tool
            result = await self._analyze_tool(target_tool, analyzers)
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning tool \'{tool_name}\' on stdio server: command="{server_config.command}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def scan_well_known_mcp_configs(
        self,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        auth: Optional[Auth] = None,
        expand_vars_default: Optional[str] = None,
    ) -> Dict[str, List[ToolScanResult]]:
        """Scan all well-known MCP configuration files and their servers.

        Args:
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.

        Returns:
            Dict[str, List[ToolScanResult]]: Dictionary mapping config file paths to scan results.
        """
        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        config_scanner = MCPConfigScanner()
        configs = await config_scanner.scan_well_known_paths()

        all_results = {}

        for config_path, config in configs.items():
            logger.debug(f"Scanning servers from config: {config_path}")
            servers = config_scanner.extract_servers(config)
            config_results = []

            for server_name, server_config in servers.items():
                logger.debug(f"Scanning server '{server_name}' from {config_path}")

                try:
                    if isinstance(server_config, StdioServer):
                        # Apply default expand mode if not provided by config
                        if expand_vars_default and not server_config.expand_vars:
                            logger.debug(f"Applying expand_vars='{expand_vars_default}' to server '{server_name}'")
                            server_config.expand_vars = expand_vars_default
                        else:
                            logger.debug(f"Server '{server_name}' expand_vars: {server_config.expand_vars} (default: {expand_vars_default})")
                            
                        # Scan stdio server with timeout and error recovery
                        try:
                            results = await self.scan_stdio_server_tools(
                                server_config, analyzers
                            )
                            # Add server name and source to each result
                            for result in results:
                                result.server_name = server_name
                                result.server_source = config_path
                            config_results.extend(results)
                        except (
                            ConnectionError,
                            asyncio.TimeoutError,
                            asyncio.CancelledError,
                        ) as e:
                            logger.warning(
                                f"Failed to connect to server '{server_name}': {e}"
                            )
                            logger.debug(f"Continuing with remaining servers...")
                            continue
                    elif isinstance(server_config, RemoteServer):
                        # Scan remote server
                        try:
                            results = await self.scan_remote_server_tools(
                                server_config.url, auth=auth, analyzers=analyzers
                            )
                            # Add server name and source to each result
                            for result in results:
                                result.server_name = server_name
                                result.server_source = config_path
                            config_results.extend(results)
                        except (
                            ConnectionError,
                            asyncio.TimeoutError,
                            asyncio.CancelledError,
                        ) as e:
                            logger.warning(
                                f"Failed to connect to server '{server_name}': {e}"
                            )
                            logger.debug(f"Continuing with remaining servers...")
                            continue
                    else:
                        logger.warning(
                            f"Unknown server type for '{server_name}' in {config_path}"
                        )

                except Exception as e:
                    logger.error(
                        f"Unexpected error scanning server '{server_name}' from {config_path}: {e}"
                    )
                    logger.debug(f"Continuing with remaining servers...")
                    continue

            all_results[config_path] = config_results

        return all_results

    async def scan_mcp_config_file(
        self,
        config_path: str,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        auth: Optional[Auth] = None,
        expand_vars_default: Optional[str] = None,
    ) -> List[ToolScanResult]:
        """Scan all servers in a specific MCP configuration file.

        Args:
            config_path (str): Path to the MCP configuration file.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.

        Returns:
            List[ToolScanResult]: The results of scanning all servers in the config file.
        """
        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        config_scanner = MCPConfigScanner()
        config = await config_scanner.scan_specific_path(config_path)

        if not config:
            raise ValueError(f"Could not parse MCP configuration file: {config_path}")

        servers = config_scanner.extract_servers(config)
        all_results = []

        for server_name, server_config in servers.items():
            logger.debug(f"Scanning server '{server_name}' from {config_path}")

            try:
                if isinstance(server_config, StdioServer):
                    # Apply default expand mode if not provided by config
                    if expand_vars_default and not server_config.expand_vars:
                        logger.debug(f"Applying expand_vars='{expand_vars_default}' to server '{server_name}'")
                        server_config.expand_vars = expand_vars_default
                    else:
                        logger.debug(f"Server '{server_name}' expand_vars: {server_config.expand_vars} (default: {expand_vars_default})")
                        
                    # Scan stdio server with timeout and error recovery
                    try:
                        results = await self.scan_stdio_server_tools(
                            server_config, analyzers
                        )
                        # Add server name and source to each result
                        for result in results:
                            result.server_name = server_name
                            result.server_source = config_path
                        all_results.extend(results)
                    except (
                        ConnectionError,
                        asyncio.TimeoutError,
                        asyncio.CancelledError,
                    ) as e:
                        logger.warning(
                            f"Failed to connect to server '{server_name}': {e}"
                        )
                        logger.debug(f"Continuing with remaining servers...")
                        continue
                elif isinstance(server_config, RemoteServer):
                    # Scan remote server
                    try:
                        results = await self.scan_remote_server_tools(
                            server_config.url, auth=auth, analyzers=analyzers
                        )
                        # Add server name and source to each result
                        for result in results:
                            result.server_name = server_name
                            result.server_source = config_path
                        all_results.extend(results)
                    except (
                        ConnectionError,
                        asyncio.TimeoutError,
                        asyncio.CancelledError,
                    ) as e:
                        logger.warning(
                            f"Failed to connect to server '{server_name}': {e}"
                        )
                        logger.debug(f"Continuing with remaining servers...")
                        continue
                else:
                    logger.warning(
                        f"Unknown server type for '{server_name}' in {config_path}"
                    )

            except Exception as e:
                logger.error(
                    f"Unexpected error scanning server '{server_name}' from {config_path}: {e}"
                )
                logger.debug(f"Continuing with remaining servers...")
                continue

        return all_results

    async def scan_remote_server_prompts(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
    ) -> List[PromptScanResult]:
        """Scan all prompts on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            List[PromptScanResult]: The results of the scan for each prompt.

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the server URL is invalid or empty.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(server_url, auth)

            # List all prompts
            try:
                prompt_list = await session.list_prompts()
            except McpError as e:
                if self._is_missing_capability_error(e):
                    logger.warning(
                        f"Server '{server_url}' does not expose prompts: {e}"
                    )
                    return []
                raise

            # Analyze each prompt with individual error handling
            scan_results = []
            for prompt in prompt_list.prompts:
                try:
                    result = await self._analyze_prompt(prompt, analyzers, http_headers)
                    scan_results.append(result)
                except Exception as e:
                    logger.error(f"Error analyzing prompt '{prompt.name}': {e}")
                    # Create a failed result for this prompt
                    scan_results.append(PromptScanResult(
                        prompt_name=prompt.name,
                        prompt_description=prompt.description or "",
                        status="failed",
                        analyzers=[],
                        findings=[],
                    ))

            return scan_results

        except Exception as e:
            logger.error(f"Error scanning prompts on server {server_url}: {e}")
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def scan_remote_server_prompt(
        self,
        server_url: str,
        prompt_name: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
    ) -> PromptScanResult:
        """Scan a specific prompt on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            prompt_name (str): The name of the prompt to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            PromptScanResult: The result of the scan.

        Raises:
            ValueError: If the prompt is not found on the server.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(server_url, auth)

            # List all prompts and find the target prompt
            try:
                prompt_list = await session.list_prompts()
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = (
                        f"Server '{server_url}' does not expose prompts; cannot scan '{prompt_name}'."
                    )
                    logger.warning(message)
                    raise ValueError(message) from e
                raise
            target_prompt = next(
                (p for p in prompt_list.prompts if p.name == prompt_name), None
            )

            if not target_prompt:
                raise ValueError(
                    f"Prompt '{prompt_name}' not found on the server at {server_url}"
                )

            # Analyze the prompt
            result = await self._analyze_prompt(target_prompt, analyzers, http_headers)
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning prompt \'{prompt_name}\' on MCP server: server="{server_url}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def scan_remote_server_instructions(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
    ) -> InstructionsScanResult:
        """Scan server instructions from the InitializeResult.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API, YARA, and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            InstructionsScanResult: The result of the scan.

        Raises:
            ValueError: If the server does not provide instructions.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to all analyzers including LLM for instructions
        # Instructions benefit from semantic analysis
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(server_url, auth)

            # Get the initialize result which was stored during session initialization
            init_result = getattr(session, '_init_result', None)
            
            if not init_result:
                raise ValueError(
                    f"Failed to get initialization result from server at {server_url}"
                )

            # Extract instructions from the initialize result
            instructions = getattr(init_result, 'instructions', None)
            
            if not instructions:
                # Return a result with no findings if instructions are not provided
                logger.info(f"Server at {server_url} does not provide instructions field")
                return InstructionsScanResult(
                    instructions="",
                    server_name=getattr(init_result.serverInfo, 'name', 'Unknown') if hasattr(init_result, 'serverInfo') else 'Unknown',
                    protocol_version=getattr(init_result, 'protocolVersion', 'Unknown'),
                    status="skipped",
                    analyzers=[],
                    findings=[],
                )

            # Extract server info
            server_name = getattr(init_result.serverInfo, 'name', 'Unknown') if hasattr(init_result, 'serverInfo') else 'Unknown'
            protocol_version = getattr(init_result, 'protocolVersion', 'Unknown')

            # Analyze the instructions
            result = await self._analyze_instructions(
                instructions=instructions,
                server_name=server_name,
                protocol_version=protocol_version,
                analyzers=analyzers,
                http_headers=http_headers
            )
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning instructions on MCP server: server="{server_url}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def scan_stdio_server_prompts(
        self,
        server_config: StdioServer,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
    ) -> List[PromptScanResult]:
        """Scan prompts from a stdio MCP server.

        Args:
            server_config: The stdio server configuration
            analyzers: List of analyzers to use (defaults to API and LLM)
            timeout: Connection timeout in seconds

        Returns:
            List of prompt scan results
        """
        if timeout is None:
            timeout = 60

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            # Create a new task for the connection to isolate async contexts
            async def connect_and_scan():
                nonlocal client_context, session
                client_context, session = await self._get_stdio_session(
                    server_config, timeout
                )

                # List all prompts
                try:
                    prompt_list = await session.list_prompts()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            f"Stdio server '{server_config.command}' does not expose prompts: {e}"
                        )
                        return []
                    raise

                # Create analysis tasks for each prompt
                scan_tasks = [
                    self._analyze_prompt(prompt, analyzers) for prompt in prompt_list.prompts
                ]

                # Run all tasks concurrently
                scan_results = await asyncio.gather(*scan_tasks)
                return scan_results

            # Run the connection and scanning in an isolated task
            return await connect_and_scan()

        except Exception as e:
            logger.error(f"Error scanning prompts on stdio server {server_config.command}: {e}")
            raise
        finally:
            # Always clean up resources
            await self._close_mcp_session(client_context, session)

    async def scan_stdio_server_prompt(
        self,
        server_config: StdioServer,
        prompt_name: str,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
    ) -> PromptScanResult:
        """Scan a specific prompt on a stdio MCP server.

        Args:
            server_config (StdioServer): The stdio server configuration.
            prompt_name (str): The name of the prompt to scan.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            timeout (Optional[int]): Timeout for the connection.

        Returns:
            PromptScanResult: The result of the scan.

        Raises:
            ValueError: If the prompt is not found on the server.
        """
        if not server_config.command:
            raise ValueError("No command provided in stdio server configuration.")

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_stdio_session(
                server_config, timeout
            )

            # List all prompts and find the target prompt
            try:
                prompt_list = await session.list_prompts()
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = (
                        f"Stdio server '{server_config.command}' does not expose prompts; cannot scan '{prompt_name}'."
                    )
                    logger.warning(message)
                    raise ValueError(message) from e
                raise
            target_prompt = next(
                (p for p in prompt_list.prompts if p.name == prompt_name), None
            )

            if not target_prompt:
                raise ValueError(
                    f"Prompt '{prompt_name}' not found on the stdio server with command {server_config.command}"
                )

            # Analyze the prompt
            result = await self._analyze_prompt(target_prompt, analyzers)
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning prompt \'{prompt_name}\' on stdio server: command="{server_config.command}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def _analyze_resource(
        self,
        resource_content: str,
        resource_uri: str,
        resource_name: str,
        resource_description: str,
        resource_mime_type: str,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> ResourceScanResult:
        """Analyze a single MCP resource using specified analyzers.

        Args:
            resource_content (str): The content of the resource to analyze.
            resource_uri (str): The URI of the resource.
            resource_name (str): The name of the resource.
            resource_description (str): The description of the resource.
            resource_mime_type (str): The MIME type of the resource.
            analyzers (List[AnalyzerEnum]): List of analyzers to run (only API and LLM supported for resources).
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            ResourceScanResult: The result of the analysis.
        """
        all_findings = []

        # Extract text from HTML if needed
        analysis_content = resource_content
        if resource_mime_type == "text/html":
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resource_content, 'html.parser')
                # Extract text content from HTML
                analysis_content = soup.get_text(separator='\n', strip=True)
                logger.info(f"Extracted text from HTML resource: {resource_uri}")
            except ImportError:
                logger.warning("BeautifulSoup not installed, analyzing raw HTML content")
                analysis_content = resource_content
            except (ValueError, TypeError) as e:
                logger.warning(f"Error parsing HTML for resource '{resource_uri}': {e}. Using raw content.")
                analysis_content = resource_content
            except Exception as e:
                logger.error(f"Unexpected error extracting text from HTML '{resource_uri}': {e}. Using raw content.")
                analysis_content = resource_content

        # Only API and LLM analyzers are used for resources
        if AnalyzerEnum.API in analyzers and self._api_analyzer:
            # Run API analysis on the resource content
            try:
                api_context = {
                    "resource_uri": resource_uri,
                    "resource_name": resource_name,
                    "resource_description": resource_description,
                    "mime_type": resource_mime_type
                }
                api_findings = await self._api_analyzer.analyze(
                    analysis_content, api_context
                )
                for finding in api_findings:
                    finding.analyzer = "API"
                all_findings.extend(api_findings)
            except Exception as e:
                logger.error(
                    f'API analysis failed on resource: uri="{resource_uri}", error="{e}"'
                )

        if AnalyzerEnum.LLM in analyzers and self._llm_analyzer:
            # Run LLM analysis on the resource content
            try:
                # Format content for comprehensive analysis
                llm_content = f"Resource URI: {resource_uri}\n"
                llm_content += f"Resource Name: {resource_name}\n"
                if resource_description:
                    llm_content += f"Description: {resource_description}\n"
                llm_content += f"MIME Type: {resource_mime_type}\n"
                llm_content += f"Content:\n{analysis_content[:2000]}\n"  # Limit content size

                llm_context = {
                    "resource_uri": resource_uri,
                    "resource_name": resource_name,
                    "resource_description": resource_description,
                    "mime_type": resource_mime_type
                }
                llm_findings = await self._llm_analyzer.analyze(
                    llm_content, llm_context
                )
                for finding in llm_findings:
                    finding.analyzer = "LLM"
                all_findings.extend(llm_findings)
            except Exception as e:
                logger.error(f'LLM analysis failed: resource="{resource_uri}", error="{e}"')
        elif AnalyzerEnum.LLM in analyzers and not self._llm_analyzer:
            logger.warning(
                f"LLM scan requested for resource '{resource_uri}' but LLM analyzer not initialized (MCP_SCANNER_LLM_API_KEY missing)"
            )

        # Run custom analyzers
        custom_analyzer_names = []
        for analyzer in self._custom_analyzers:
            try:
                custom_context = {
                    "resource_uri": resource_uri,
                    "resource_name": resource_name,
                    "resource_description": resource_description,
                    "mime_type": resource_mime_type
                }
                # Add HTTP headers to context for custom analyzers
                if http_headers:
                    custom_context["http_headers"] = http_headers
                findings = await analyzer.analyze(analysis_content, custom_context)
                for finding in findings:
                    finding.analyzer = analyzer.name
                all_findings.extend(findings)
                # Track which custom analyzers were successfully run
                custom_analyzer_names.append(analyzer.name)
            except Exception as e:
                logger.error(
                    f'Custom analyzer "{analyzer.name}" failed: resource="{resource_uri}", error="{e}"'
                )

        # Combine enum analyzers and custom analyzer names (filter out YARA if present)
        active_analyzers = [a for a in analyzers if a in [AnalyzerEnum.API, AnalyzerEnum.LLM]]
        all_analyzers = active_analyzers + custom_analyzer_names

        return ResourceScanResult(
            resource_uri=resource_uri,
            resource_name=resource_name,
            resource_mime_type=resource_mime_type,
            status="completed",
            analyzers=all_analyzers,
            findings=all_findings,
        )

    async def scan_remote_server_resources(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        allowed_mime_types: Optional[List[str]] = None,
    ) -> List[ResourceScanResult]:
        """Scan all resources on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.
            allowed_mime_types (Optional[List[str]]): List of allowed MIME types to scan. Defaults to text/plain and text/html.

        Returns:
            List[ResourceScanResult]: The results of the scan for each resource.

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the server URL is invalid or empty.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to API and LLM analyzers for resources
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Default allowed MIME types
        if allowed_mime_types is None:
            allowed_mime_types = ["text/plain", "text/html"]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(server_url, auth)

            # List all resources
            try:
                resource_list = await session.list_resources()
            except McpError as e:
                if self._is_missing_capability_error(e):
                    logger.warning(
                        f"Server '{server_url}' does not expose resources: {e}"
                    )
                    return []
                raise

            results = []
            for resource in resource_list.resources:
                # Check if MIME type is allowed
                if resource.mimeType and resource.mimeType not in allowed_mime_types:
                    logger.info(f"Skipping resource '{resource.uri}' with MIME type '{resource.mimeType}'")
                    results.append(ResourceScanResult(
                        resource_uri=resource.uri,
                        resource_name=resource.name or "",
                        resource_mime_type=resource.mimeType or "unknown",
                        status="skipped",
                        analyzers=[],
                        findings=[],
                    ))
                    continue

                # Read resource content
                try:
                    resource_contents = await session.read_resource(resource.uri)

                    # Extract text content
                    text_content = ""
                    try:
                        for content in resource_contents.contents:
                            if hasattr(content, 'text'):
                                text_content += content.text
                            elif hasattr(content, 'blob'):
                                # Skip binary content
                                logger.info(f"Skipping binary content for resource '{resource.uri}'")
                                continue
                    except (AttributeError, TypeError) as e:
                        logger.warning(f"Error extracting content from resource '{resource.uri}': {e}")
                        results.append(ResourceScanResult(
                            resource_uri=resource.uri,
                            resource_name=resource.name or "",
                            resource_mime_type=resource.mimeType or "unknown",
                            status="failed",
                            analyzers=[],
                            findings=[],
                        ))
                        continue

                    if not text_content:
                        logger.info(f"No text content found for resource '{resource.uri}'")
                        results.append(ResourceScanResult(
                            resource_uri=resource.uri,
                            resource_name=resource.name or "",
                            resource_mime_type=resource.mimeType or "unknown",
                            status="skipped",
                            analyzers=[],
                            findings=[],
                        ))
                        continue

                    # Analyze the resource
                    try:
                        result = await self._analyze_resource(
                            text_content,
                            resource.uri,
                            resource.name or "",
                            resource.description or "",
                            resource.mimeType or "unknown",
                            analyzers,
                            http_headers
                        )
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Error analyzing resource '{resource.uri}': {e}")
                        results.append(ResourceScanResult(
                            resource_uri=resource.uri,
                            resource_name=resource.name or "",
                            resource_mime_type=resource.mimeType or "unknown",
                            status="failed",
                            analyzers=[],
                            findings=[],
                        ))

                except asyncio.TimeoutError:
                    logger.error(f"Timeout reading resource '{resource.uri}'")
                    results.append(ResourceScanResult(
                        resource_uri=resource.uri,
                        resource_name=resource.name or "",
                        resource_mime_type=resource.mimeType or "unknown",
                        status="failed",
                        analyzers=[],
                        findings=[],
                    ))
                except Exception as e:
                    logger.error(f"Error reading resource '{resource.uri}': {e}")
                    results.append(ResourceScanResult(
                        resource_uri=resource.uri,
                        resource_name=resource.name or "",
                        resource_mime_type=resource.mimeType or "unknown",
                        status="failed",
                        analyzers=[],
                        findings=[],
                    ))

            return results

        except Exception as e:
            logger.error(f"Error scanning resources on server {server_url}: {e}")
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def scan_remote_server_resource(
        self,
        server_url: str,
        resource_uri: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        allowed_mime_types: Optional[List[str]] = None,
    ) -> ResourceScanResult:
        """Scan a specific resource on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            resource_uri (str): The URI of the resource to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.
            allowed_mime_types (Optional[List[str]]): List of allowed MIME types to scan. Defaults to text/plain and text/html.

        Returns:
            ResourceScanResult: The result of the scan.

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the resource is not found on the server or server URL is invalid.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        if not resource_uri:
            raise ValueError(
                "No resource URI provided. Please specify a valid resource URI."
            )

        # Default to API and LLM analyzers for resources
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Default allowed MIME types
        if allowed_mime_types is None:
            allowed_mime_types = ["text/plain", "text/html"]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(server_url, auth)

            # List all resources to find the target
            try:
                resource_list = await session.list_resources()
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = (
                        f"Server '{server_url}' does not expose resources; cannot scan '{resource_uri}'."
                    )
                    logger.warning(message)
                    raise ValueError(message) from e
                raise

            target_resource = None
            for resource in resource_list.resources:
                # Convert AnyUrl to string for comparison
                resource_uri_str = str(resource.uri) if hasattr(resource.uri, '__str__') else resource.uri
                if resource_uri_str == resource_uri:
                    target_resource = resource
                    break

            if not target_resource:
                raise ValueError(f"Resource '{resource_uri}' not found on server {server_url}")

            # Check if MIME type is allowed
            if target_resource.mimeType and target_resource.mimeType not in allowed_mime_types:
                logger.info(f"Resource '{resource_uri}' has unsupported MIME type '{target_resource.mimeType}'")
                return ResourceScanResult(
                    resource_uri=target_resource.uri,
                    resource_name=target_resource.name or "",
                    resource_mime_type=target_resource.mimeType or "unknown",
                    status="skipped",
                    analyzers=[],
                    findings=[],
                )

            # Read resource content
            try:
                resource_contents = await session.read_resource(target_resource.uri)

                # Extract text content
                text_content = ""
                try:
                    for content in resource_contents.contents:
                        if hasattr(content, 'text'):
                            text_content += content.text
                        elif hasattr(content, 'blob'):
                            logger.info(f"Skipping binary content for resource '{resource_uri}'")
                            continue
                except (AttributeError, TypeError) as e:
                    logger.warning(f"Error extracting content from resource '{resource_uri}': {e}")
                    return ResourceScanResult(
                        resource_uri=target_resource.uri,
                        resource_name=target_resource.name or "",
                        resource_mime_type=target_resource.mimeType or "unknown",
                        status="failed",
                        analyzers=[],
                        findings=[],
                    )

                if not text_content:
                    logger.info(f"No text content found for resource '{resource_uri}'")
                    return ResourceScanResult(
                        resource_uri=target_resource.uri,
                        resource_name=target_resource.name or "",
                        resource_mime_type=target_resource.mimeType or "unknown",
                        status="skipped",
                        analyzers=[],
                        findings=[],
                    )

                # Analyze the resource
                result = await self._analyze_resource(
                    text_content,
                    target_resource.uri,
                    target_resource.name or "",
                    target_resource.description or "",
                    target_resource.mimeType or "unknown",
                    analyzers,
                    http_headers
                )
                return result

            except asyncio.TimeoutError:
                logger.error(f"Timeout reading resource '{resource_uri}'")
                return ResourceScanResult(
                    resource_uri=target_resource.uri,
                    resource_name=target_resource.name or "",
                    resource_mime_type=target_resource.mimeType or "unknown",
                    status="failed",
                    analyzers=[],
                    findings=[],
                )
            except Exception as e:
                logger.error(f"Error reading resource '{resource_uri}': {e}")
                return ResourceScanResult(
                    resource_uri=target_resource.uri,
                    resource_name=target_resource.name or "",
                    resource_mime_type=target_resource.mimeType or "unknown",
                    status="failed",
                    analyzers=[],
                    findings=[],
                )

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error scanning resource '{resource_uri}' on server {server_url}: {e}")
            raise
        finally:
            await self._close_mcp_session(client_context, session)