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

"""MCP Configuration Models for MCP Scanner SDK.

This module contains Pydantic models for MCP server configurations
and related data structures.
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ServerSignature(BaseModel):
    """Signature information for an MCP server."""

    metadata: Dict[str, Any] = Field(default_factory=dict)
    prompts: List[Dict[str, Any]] = Field(default_factory=list)
    resources: List[Dict[str, Any]] = Field(default_factory=list)
    resource_templates: List[Dict[str, Any]] = Field(default_factory=list)
    tools: List[Dict[str, Any]] = Field(default_factory=list)


class StdioServer(BaseModel):
    """Configuration for stdio-based MCP servers."""

    command: str
    args: List[str] = Field(default_factory=list)
    env: Optional[Dict[str, str]] = None
    expand_vars: Optional[str] = None
    type: str = "stdio"


class RemoteServer(BaseModel):
    """Configuration for remote MCP servers."""

    url: str
    headers: Optional[Dict[str, str]] = None
    env: Optional[Dict[str, str]] = None
    type: Optional[str] = None


class MCPConfig(BaseModel):
    """Base MCP configuration."""

    mcpServers: Dict[str, Union[StdioServer, RemoteServer]] = Field(
        default_factory=dict
    )


class ClaudeConfigFile(MCPConfig):
    """Claude desktop configuration file format."""

    pass


class VSCodeMCPConfig(MCPConfig):
    """VSCode MCP configuration format."""

    pass


class VSCodeConfigFile(BaseModel):
    """VSCode settings.json configuration file format."""

    mcp: Optional[VSCodeMCPConfig] = None
