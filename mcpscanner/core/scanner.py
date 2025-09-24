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
from typing import Any, Dict, List, Optional, Tuple, Callable

# MCP client imports
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Tool as MCPTool
from mcp import StdioServerParameters

from ..config.config import Config
from ..utils.logging_config import get_logger
from .analyzers.api_analyzer import ApiAnalyzer
from .analyzers.base import BaseAnalyzer
from .analyzers.llm_analyzer import LLMAnalyzer
from .analyzers.yara_analyzer import YaraAnalyzer
from .auth import (
    Auth,
    AuthType,
    create_oauth_provider_from_auth,
)
from .models import AnalyzerEnum
from .mcp_models import StdioServer, RemoteServer
from ..config.config_parser import MCPConfigScanner
from .result import ScanResult

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
        self._llm_analyzer = (
            LLMAnalyzer(config) if config.llm_provider_api_key else None
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
                "LLM analyzer requested but MCP_SCANNER_LLM_API_KEY not configured"
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

    async def _analyze_tool(
        self,
        tool: MCPTool,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> ScanResult:
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

        return ScanResult(
            tool_name=name,
            tool_description=description,
            status="completed",
            analyzers=all_analyzers,
            findings=all_findings,
        )

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
            except Exception as e:
                logger.warning(f"Error closing session: {e}")

        # Close client context
        if client_context:
            try:
                # Ensure we're in the same task context for cleanup
                await client_context.__aexit__(None, None, None)
            except Exception as e:
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
            elif auth:
                logger.debug(
                    f'Using explicit authentication (type: {auth.type}) for MCP server: server="{server_url}"'
                )
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
        try:
            logger.debug(f'Attempting to connect to MCP server: server="{server_url}"')
            client_context_opened = await client_context.__aenter__()
            streams = client_context_opened
            read, write, *_ = streams
            session = ClientSession(read, write)
            await session.__aenter__()
            logger.debug(f'Initializing MCP session: server="{server_url}"')
            await session.initialize()
            logger.debug(f'Successfully connected to MCP server: server="{server_url}"')
            return client_context, session
        except Exception as e:
            if session:
                try:
                    await session.__aexit__(None, None, None)
                except Exception:
                    pass
            if client_context_opened:
                try:
                    await client_context.__aexit__(None, None, None)
                except Exception:
                    pass

            if "ConnectError" in str(type(e)) or "connection" in str(e).lower():
                raise ConnectionError(
                    f"Unable to connect to MCP server at {server_url}. "
                    f"Please verify the server is running and accessible. "
                    f"Original error: {e}"
                ) from e
            raise

    async def scan_remote_server_tool(
        self,
        server_url: str,
        tool_name: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
    ) -> ScanResult:
        """Scan a specific tool on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            tool_name (str): The name of the tool to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.

        Returns:
            ScanResult: The result of the scan.

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
            tool_list = await session.list_tools()
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
    ) -> List[ScanResult]:
        """Scan all tools on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.

        Returns:
            List[ScanResult]: The results of the scan for each tool.

        Raises:
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
            tool_list = await session.list_tools()

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

            server_params = StdioServerParameters(
                command=server_config.command,
                args=server_config.args,
                env=server_config.env,
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
            raise ConnectionError(
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
            raise ConnectionError(
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
            raise ConnectionError(
                f"Unable to connect to stdio MCP server with command {server_config.command}. "
                f"Please verify the command is correct and executable. "
                f"Original error: {e}"
            ) from e

    async def scan_stdio_server_tools(
        self,
        server_config: StdioServer,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
    ) -> List[ScanResult]:
        """Scan tools from a stdio MCP server.

        Args:
            server_config: The stdio server configuration
            analyzers: List of analyzers to use
            timeout: Connection timeout in seconds

        Returns:
            List of scan results
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
                tool_list = await session.list_tools()

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
    ) -> ScanResult:
        """Scan a specific tool on a stdio MCP server.

        Args:
            server_config (StdioServer): The stdio server configuration.
            tool_name (str): The name of the tool to scan.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.
            timeout (Optional[int]): Timeout for the connection.

        Returns:
            ScanResult: The result of the scan.

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
            tool_list = await session.list_tools()
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
    ) -> Dict[str, List[ScanResult]]:
        """Scan all well-known MCP configuration files and their servers.

        Args:
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.

        Returns:
            Dict[str, List[ScanResult]]: Dictionary mapping config file paths to scan results.
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
    ) -> List[ScanResult]:
        """Scan all servers in a specific MCP configuration file.

        Args:
            config_path (str): Path to the MCP configuration file.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.

        Returns:
            List[ScanResult]: The results of scanning all servers in the config file.
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
