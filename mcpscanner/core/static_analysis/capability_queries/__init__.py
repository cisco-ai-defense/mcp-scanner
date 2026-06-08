# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tree-sitter ``.scm`` queries for MCP capability detection.

Queries replace the imperative tree walks that previously lived in
:mod:`mcpscanner.core.static_analysis.capability_detector`. Each
language has its own subdirectory containing:

* ``registrations.scm``   — call-site registrations such as
  ``server.tool(...)``.
* ``low_level.scm``       — low-level SDK registrations such as
  ``server.setRequestHandler(SchemaIdentifier, handler)``.
* ``functions.scm``       — function/method/arrow definitions used to
  build the per-file ``name -> definition`` index.
* ``instantiations.scm``  — declarations that bind MCP server
  instances to local names (``new McpServer(...)``,
  ``mcp.NewServer(...)``, etc.).
* ``annotations.scm``     — function-attached annotations and
  attribute lists used for the annotation pre-index.

Receiver-type verification (``_ts_receiver_is_trusted``) and
SDK-import bookkeeping stay in Python: queries cover *what* is in the
tree, semantic checks live with the existing imports/instances state.
This module hosts only the loader and the language-to-query mapping.
"""

from __future__ import annotations

from .loader import (
    CapabilityQueryLoader,
    QueryBundle,
    QUERY_NAMES,
    SUPPORTED_LANGUAGES,
    get_bundle,
    get_loader,
)

__all__ = [
    "CapabilityQueryLoader",
    "QueryBundle",
    "QUERY_NAMES",
    "SUPPORTED_LANGUAGES",
    "get_bundle",
    "get_loader",
]
