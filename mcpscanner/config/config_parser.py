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

"""MCP Configuration Parser for MCP Scanner SDK.

This module provides functionality to parse MCP configuration files
from various clients and formats.
"""

import json
import os
from typing import Dict, List, Optional, Union
from pydantic import ValidationError

try:
    import pyjson5

    HAS_JSON5 = True
except ImportError:
    HAS_JSON5 = False

from ..utils.logging_config import get_logger
from .constants import CONSTANTS
from ..core.mcp_models import (
    ClaudeConfigFile,
    MCPConfig,
    StdioServer,
    RemoteServer,
    VSCodeConfigFile,
    VSCodeMCPConfig,
)

logger = get_logger(__name__)


def rebalance_command_args(command: str, args: List[str]) -> tuple[str, List[str]]:
    """Rebalance command and args to handle complex configurations.

    Args:
        command: The command string
        args: List of arguments

    Returns:
        Tuple of (command, args)
    """
    if not command:
        return command, args

    # Handle cases where command might contain spaces
    command_parts = command.split()
    if len(command_parts) > 1:
        return command_parts[0], command_parts[1:] + args

    return command, args


async def scan_mcp_config_file(path: str) -> MCPConfig:
    """Scan and parse an MCP config file.

    Args:
        path: Path to the config file

    Returns:
        Parsed MCP configuration

    Raises:
        Exception: If the file cannot be parsed
    """
    logger.debug(f"Scanning MCP config file: {path}")
    path = os.path.expanduser(path)

    def parse_and_validate(config: dict) -> MCPConfig:
        """Parse and validate config with lenient server filtering."""
        # Check if this looks like a Claude config (has mcpServers at root)
        if "mcpServers" in config:
            # Filter out invalid server entries
            valid_servers = {}
            invalid_count = 0

            for name, server_config in config["mcpServers"].items():
                try:
                    # Try to validate as either StdioServer or RemoteServer
                    if isinstance(server_config, dict):
                        if "url" in server_config:
                            # Try RemoteServer
                            RemoteServer.model_validate(server_config)
                            valid_servers[name] = server_config
                        elif "command" in server_config:
                            # Try StdioServer
                            StdioServer.model_validate(server_config)
                            valid_servers[name] = server_config
                        else:
                            invalid_count += 1
                            logger.debug(
                                f"Skipping invalid server '{name}': missing url or command"
                            )
                    else:
                        invalid_count += 1
                        logger.debug(f"Skipping invalid server '{name}': not a dict")
                except ValidationError:
                    invalid_count += 1
                    logger.debug(f"Skipping invalid server '{name}': validation failed")

            logger.debug(
                f"Found {len(valid_servers)} valid servers, skipped {invalid_count} invalid entries"
            )

            # Create a cleaned config with only valid servers
            cleaned_config = {"mcpServers": valid_servers}
            return ClaudeConfigFile.model_validate(cleaned_config)

        # Fall back to original validation for other formats
        models = [VSCodeConfigFile, VSCodeMCPConfig]
        validation_errors = []

        for model in models:
            try:
                result = model.model_validate(config)
                if isinstance(result, VSCodeConfigFile) and result.mcp is None:
                    continue
                return result
            except ValidationError as e:
                validation_errors.append(f"{model.__name__}: {str(e)}")
                continue

        error_msg = "Could not parse config file as any supported format"
        logger.debug(f"Validation errors: {validation_errors}")
        raise Exception(error_msg)

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Try JSON5 first if available (supports comments)
        if HAS_JSON5:
            try:
                config = pyjson5.loads(content)
            except Exception:
                config = json.loads(content)
        else:
            config = json.loads(content)

        # Try to parse model
        result = parse_and_validate(config)
        logger.debug("Config file parsed and validated successfully")
        return result

    except Exception as e:
        logger.exception(f"Error processing config file {path}")
        raise


class MCPConfigScanner:
    """Scanner for MCP configuration files."""

    def __init__(self):
        """Initialize the config scanner."""
        self.constants = CONSTANTS

    async def scan_well_known_paths(self) -> Dict[str, MCPConfig]:
        """Scan all well-known MCP configuration paths.

        Returns:
            Dictionary mapping file paths to parsed configurations
        """
        results = {}
        well_known_paths = self.constants.get_well_known_mcp_paths()

        for path in well_known_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                try:
                    logger.debug(f"Found MCP config file: {expanded_path}")
                    config = await scan_mcp_config_file(expanded_path)
                    results[expanded_path] = config
                except Exception as e:
                    logger.warning(f"Failed to parse config file {expanded_path}: {e}")
            else:
                logger.warning(f"Config file not found: {expanded_path}")

        return results

    async def scan_specific_path(self, path: str) -> Optional[MCPConfig]:
        """Scan a specific MCP configuration file.

        Args:
            path: Path to the configuration file

        Returns:
            Parsed configuration or None if failed
        """
        try:
            return await scan_mcp_config_file(path)
        except Exception as e:
            logger.error(f"Failed to scan config file {path}: {e}")
            return None

    def extract_servers(
        self, config: MCPConfig
    ) -> Dict[str, Union[StdioServer, RemoteServer]]:
        """Extract server configurations from parsed config.

        Args:
            config: Parsed MCP configuration

        Returns:
            Dictionary of server configurations
        """
        if hasattr(config, "mcpServers"):
            return config.mcpServers
        elif (
            hasattr(config, "mcp") and config.mcp and hasattr(config.mcp, "mcpServers")
        ):
            return config.mcp.mcpServers
        else:
            return {}
