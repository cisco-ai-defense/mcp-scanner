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

"""Post-parse setup: analyzer selection, logging, and credential env vars."""

import argparse
import logging
import os
import sys
from typing import List

from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.utils.logging_config import get_logger, set_log_level

logger = get_logger(__name__)


def configure_runtime(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> List[AnalyzerEnum]:
    """Validate analyzer selection and apply logging/credential side effects.

    Returns the analyzers the run should use. Exits through
    ``parser.error`` when the ``--analyzers`` list names something unknown.
    """
    # Parse analyzers argument into AnalyzerEnum list
    analyzer_names = [a.strip().lower() for a in args.analyzers.split(",")]
    valid_analyzer_names = {e.value for e in AnalyzerEnum}

    # Validate analyzer names
    invalid_analyzers = set(analyzer_names) - valid_analyzer_names
    if invalid_analyzers:
        parser.error(
            "Invalid analyzers: %s. Valid options: %s",
            ", ".join(invalid_analyzers),
            ", ".join(valid_analyzer_names),
        )

    # Convert to AnalyzerEnum list
    selected_analyzers = [AnalyzerEnum(name) for name in analyzer_names]

    # Add META analyzer if --enable-meta flag is set
    if (
        getattr(args, "enable_meta", False)
        and AnalyzerEnum.META not in selected_analyzers
    ):
        selected_analyzers.append(AnalyzerEnum.META)

    # Validate behavioral analyzer requirements
    if AnalyzerEnum.BEHAVIORAL in selected_analyzers:
        if not args.source_path and not (
            hasattr(args, "cmd") and args.cmd == "behavioral"
        ):
            parser.error(
                "Behavioral analyzer requires --source-path argument. "
                "Usage: mcp-scanner --source-path FILE --analyzers behavioral"
            )

    if args.log_level:
        effective_level = getattr(logging, args.log_level.upper())
        logging.basicConfig(
            level=effective_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stderr,
        )
        set_log_level(effective_level)
    elif args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stderr,
        )
        set_log_level(logging.DEBUG)
        logger.info("Verbose output enabled - detailed analyzer logs will be shown")
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stderr,
        )
        set_log_level(logging.WARNING)

    if args.api_key:
        os.environ["MCP_SCANNER_API_KEY"] = args.api_key
    if args.endpoint_url:
        os.environ["MCP_SCANNER_ENDPOINT"] = args.endpoint_url
    if args.llm_api_key:
        os.environ["MCP_SCANNER_LLM_API_KEY"] = args.llm_api_key
    if args.llm_timeout:
        os.environ["MCP_SCANNER_LLM_TIMEOUT"] = str(args.llm_timeout)
    if args.stdio_timeout:
        os.environ["MCP_SCANNER_STDIO_TIMEOUT"] = str(args.stdio_timeout)

    return selected_analyzers
