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

"""
Centralized logging configuration for MCP Scanner SDK.

This module provides consistent logging setup across all components.
"""

import logging
import sys
from typing import Optional

from ..config.constants import CONSTANTS


def setup_logger(
    name: str, level: Optional[str] = None, format_string: Optional[str] = None
) -> logging.Logger:
    """
    Set up a logger with consistent configuration.

    Args:
        name: Logger name (typically __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string, uses default if None

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Avoid adding multiple handlers to the same logger
    if logger.handlers:
        return logger

    # Check if mcpscanner root logger has been configured for debug
    mcpscanner_root = logging.getLogger("mcpscanner")
    if mcpscanner_root.level == logging.DEBUG and name.startswith("mcpscanner"):
        # Use DEBUG level if the root mcpscanner logger is set to DEBUG
        logger.setLevel(logging.DEBUG)
    elif level:
        logger.setLevel(getattr(logging, level.upper()))
    else:
        logger.setLevel(logging.INFO)

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)

    # Set formatter
    formatter = logging.Formatter(format_string or CONSTANTS.LOG_FORMAT)
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    # Prevent propagation to avoid duplicate logs
    logger.propagate = False

    return logger


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get a logger with standard configuration.

    Args:
        name: Logger name (typically __name__)
        level: Optional logging level override

    Returns:
        Configured logger instance
    """
    return setup_logger(name, level)


def set_verbose_logging(verbose: bool = False) -> None:
    """
    Enable or disable verbose logging for all mcpscanner loggers.

    Args:
        verbose: If True, set all existing mcpscanner loggers to DEBUG level
    """
    target_level = logging.DEBUG if verbose else logging.INFO

    # Set the root mcpscanner logger level
    root_logger = logging.getLogger("mcpscanner")
    root_logger.setLevel(target_level)

    # Update all existing mcpscanner loggers
    for name in list(logging.Logger.manager.loggerDict.keys()):
        if name.startswith("mcpscanner"):
            logger = logging.getLogger(name)
            logger.setLevel(target_level)
            # Update handler levels too
            for handler in logger.handlers:
                handler.setLevel(target_level)
