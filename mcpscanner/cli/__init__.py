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

"""MCP Security Scanner command line interface.

A comprehensive security scanning tool for Model Context Protocol (MCP)
servers, analyzing MCP tools for potential security findings using multiple
analysis engines including API-based classification, YARA pattern matching,
and LLM-powered threat detection.

Layout:

- :mod:`~mcpscanner.cli.parser` builds the argument parser.
- :mod:`~mcpscanner.cli.runtime` turns parsed arguments into run settings.
- :mod:`~mcpscanner.cli.dispatch` picks a handler from
  :mod:`~mcpscanner.cli.commands`.
- :mod:`~mcpscanner.cli.output` renders whatever the handler returned.
"""

from dotenv import load_dotenv

from .app import cli_entry_point, main
# Underscore-prefixed names are re-exported because callers outside this
# package already import them from ``mcpscanner.cli``.
from .config import (  # noqa: F401
    _build_config,
    _create_auth_with_headers,
    _get_endpoint_from_env,
    _parse_custom_headers,
)
from .direct import scan_mcp_server_direct
from .display import (
    display_instructions_results,
    display_instructions_results_table,
    display_prompt_results,
    display_prompt_results_table,
    display_resource_results,
    display_resource_results_table,
    display_results,
)
from .parser import build_parser
from .results import (  # noqa: F401
    _build_behavioral_results,
    _package_scan_to_tool_results,
)

load_dotenv()

__all__ = [
    "build_parser",
    "cli_entry_point",
    "display_instructions_results",
    "display_instructions_results_table",
    "display_prompt_results",
    "display_prompt_results_table",
    "display_resource_results",
    "display_resource_results_table",
    "display_results",
    "main",
    "scan_mcp_server_direct",
]
