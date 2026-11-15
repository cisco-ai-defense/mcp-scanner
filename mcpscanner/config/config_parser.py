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
import re
from typing import Any, Dict, List, Optional, Union
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


# VS Code variables in mcp.json / settings.json, e.g. ${workspaceFolder},
# ${env:NAME} or ${input:token}.
_VSCODE_VARIABLE = re.compile(r"\$\{([^{}]+)\}")


class UnresolvedVariableError(ValueError):
    """A VS Code variable that cannot be resolved outside the editor."""


def _vscode_workspace_folder(config_path: str) -> Optional[str]:
    """The workspace folder for a ``<workspace>/.vscode/*.json`` file.

    User-profile files (``Code/User/mcp.json``, ``settings.json``) belong to
    no workspace, so ``${workspaceFolder}`` has no value there.
    """
    parent = os.path.dirname(os.path.abspath(config_path))
    if os.path.basename(parent) == ".vscode":
        return os.path.dirname(parent)
    return None


def _resolve_vscode_value(value: Any, config_path: str) -> Any:
    """Substitute the VS Code variables that have a value outside the editor.

    Supports ``${workspaceFolder}``, ``${workspaceFolderBasename}``,
    ``${userHome}``, ``${env:NAME}`` (empty when unset, as in VS Code),
    ``${pathSeparator}`` and ``${/}``. Anything else, such as
    ``${input:...}``, ``${command:...}`` or ``${config:...}``, needs the
    editor and raises :class:`UnresolvedVariableError`.
    """
    if isinstance(value, dict):
        return {k: _resolve_vscode_value(v, config_path) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_vscode_value(v, config_path) for v in value]
    if not isinstance(value, str) or "${" not in value:
        return value

    workspace = _vscode_workspace_folder(config_path)

    def substitute(match: "re.Match[str]") -> str:
        name = match.group(1)
        if name in ("workspaceFolder", "workspaceFolderBasename"):
            if workspace is None:
                raise UnresolvedVariableError(
                    f"${{{name}}} has no value outside a workspace .vscode folder"
                )
            if name == "workspaceFolder":
                return workspace
            return os.path.basename(workspace)
        if name == "userHome":
            return os.path.expanduser("~")
        if name in ("pathSeparator", "/"):
            return os.sep
        if name.startswith("env:"):
            return os.environ.get(name[len("env:") :], "")
        raise UnresolvedVariableError(f"${{{name}}} can only be resolved by VS Code")

    return _VSCODE_VARIABLE.sub(substitute, value)


def _resolve_vscode_servers(servers: Any, config_path: str) -> Any:
    """Resolve VS Code variables in each server entry.

    A variable with no value outside the editor (``${input:...}``, or
    ``${workspaceFolder}`` in a user-profile file) is never passed on as
    literal ``${...}`` text:

    - in an ``env`` or ``headers`` value, that one entry is left out, as if
      the credential were not set, and the server is still scanned;
    - anywhere else (``command``, ``args``, ``cwd``, ``url``), the server is
      skipped, because it cannot be started or reached as configured.

    Both cases log a warning naming the server and the variable.
    """
    if not isinstance(servers, dict):
        return servers
    resolved = {}
    for name, server_config in servers.items():
        if not isinstance(server_config, dict):
            resolved[name] = server_config
            continue
        entry = {}
        try:
            for key, value in server_config.items():
                if key in ("env", "headers") and isinstance(value, dict):
                    kept = {}
                    for item, item_value in value.items():
                        if key == "env":
                            # VS Code allows numbers (sent as text) and null
                            # (variable not set) as env values.
                            if item_value is None:
                                continue
                            if isinstance(item_value, (int, float)) and not isinstance(
                                item_value, bool
                            ):
                                item_value = str(item_value)
                        try:
                            kept[item] = _resolve_vscode_value(item_value, config_path)
                        except UnresolvedVariableError as e:
                            logger.warning(
                                f"Server '{name}' from {config_path}: "
                                f"leaving out {key} '{item}': {e}"
                            )
                    entry[key] = kept
                else:
                    entry[key] = _resolve_vscode_value(value, config_path)
        except UnresolvedVariableError as e:
            logger.warning(f"Skipping server '{name}' from {config_path}: {e}")
            continue
        # VS Code starts a workspace stdio server in the workspace folder
        # when the entry has no cwd of its own.
        workspace = _vscode_workspace_folder(config_path)
        is_remote = any(k.lower() in ("url", "serverurl") for k in entry)
        if workspace and "command" in entry and not is_remote and not entry.get("cwd"):
            entry["cwd"] = workspace
        resolved[name] = entry
    return resolved


def _filter_valid_servers(servers: dict) -> Dict[str, dict]:
    """Keep only the server entries that validate as a stdio or remote server.

    Args:
        servers: Mapping of server name to raw server config

    Returns:
        Mapping of server name to raw config for the valid entries
    """
    valid_servers = {}
    invalid_count = 0

    for name, server_config in servers.items():
        try:
            # Try to validate as either StdioServer or RemoteServer
            if isinstance(server_config, dict):
                # Check for any URL field variant (case-insensitive)
                has_url = any(
                    k.lower() in ("url", "serverurl") for k in server_config.keys()
                )
                if has_url:
                    # Try RemoteServer (model_validator normalizes URL field)
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
    return valid_servers


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
        # Claude, Cursor and Windsurf keep their servers under "mcpServers"
        if "mcpServers" in config:
            return ClaudeConfigFile.model_validate(
                {"mcpServers": _filter_valid_servers(config["mcpServers"])}
            )

        # VS Code uses "servers": at the top level of mcp.json, and under
        # "mcp" in settings.json, either nested or as the dotted key
        # "mcp.servers"
        if isinstance(config.get("servers"), dict):
            servers = _resolve_vscode_servers(config["servers"], path)
            return VSCodeMCPConfig.model_validate(
                {"mcpServers": _filter_valid_servers(servers)}
            )
        mcp_section = config.get("mcp")
        if isinstance(mcp_section, dict) and isinstance(
            mcp_section.get("servers"), dict
        ):
            servers = _resolve_vscode_servers(mcp_section["servers"], path)
            return VSCodeConfigFile.model_validate(
                {"mcp": {"mcpServers": _filter_valid_servers(servers)}}
            )
        if isinstance(config.get("mcp.servers"), dict):
            servers = _resolve_vscode_servers(config["mcp.servers"], path)
            return VSCodeConfigFile.model_validate(
                {"mcp": {"mcpServers": _filter_valid_servers(servers)}}
            )

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
