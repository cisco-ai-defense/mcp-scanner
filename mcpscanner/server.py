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

"""Server module for MCP Scanner SDK API.

This module provides a command-line interface for starting the API server.
Configuration is loaded from a .env file or environment variables.
"""

import argparse
import logging
import os
import sys

import uvicorn
from dotenv import load_dotenv

from .config.constants import CONSTANTS
from .utils.logging_config import set_verbose_logging

logger = logging.getLogger(__name__)


def main():
    """Main entry point for the API server."""
    # Load environment variables from .env file
    load_dotenv()

    parser = argparse.ArgumentParser(description="MCP Scanner SDK API Server")
    parser.add_argument(
        "--host",
        default=CONSTANTS.DEFAULT_SERVER_HOST,
        help="Host to bind the server to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=CONSTANTS.DEFAULT_SERVER_PORT,
        help="Port to bind the server to",
    )
    parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )
    parser.add_argument(
        "--env-file",
        default=CONSTANTS.DEFAULT_ENV_FILE,
        help="Path to .env file for configuration",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging for detailed analysis",
    )

    args = parser.parse_args()

    # Load environment variables from specified .env file if it exists
    if args.env_file and os.path.exists(args.env_file):
        load_dotenv(args.env_file)

    # Check if API key is configured
    api_key = os.environ.get(CONSTANTS.ENV_API_KEY)
    if not api_key:
        logger.warning(
            f"{CONSTANTS.ENV_API_KEY} is not set. Cisco AI Defense API analyzer will not work."
        )
        logger.warning(
            f"Please set {CONSTANTS.ENV_API_KEY} in your .env file or environment variables."
        )
    else:
        logger.debug("Cisco AI Defense API key configured successfully.")

    # Check if LLM API key is configured
    llm_api_key = os.environ.get(CONSTANTS.ENV_LLM_API_KEY)
    if not llm_api_key:
        logger.warning(
            f"{CONSTANTS.ENV_LLM_API_KEY} is not set. LLM analyzer will not work."
        )
        logger.warning(
            f"Please set {CONSTANTS.ENV_LLM_API_KEY} in your .env file or environment variables."
        )
    else:
        logger.debug("LLM API key configured successfully.")

    # Log the configured endpoint
    endpoint = os.environ.get(CONSTANTS.ENV_ENDPOINT, CONSTANTS.API_BASE_URL)
    logger.debug(f"Using endpoint: {endpoint}")

    if args.debug:
        # Set root logger to DEBUG first
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stdout,
        )
        # Set the mcpscanner root logger to DEBUG to ensure all future loggers inherit it
        logging.getLogger("mcpscanner").setLevel(logging.DEBUG)
        # Enable debug logging for existing mcpscanner components
        set_verbose_logging(True)
        logger.debug("Debug logging enabled - detailed analyzer logs will be shown")
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stdout,
        )
        # Ensure mcpscanner root logger is at WARNING level
        logging.getLogger("mcpscanner").setLevel(logging.WARNING)

    # Start the server
    uvicorn.run(
        "mcpscanner.api.api:app", host=args.host, port=args.port, reload=args.reload
    )


if __name__ == "__main__":
    main()
