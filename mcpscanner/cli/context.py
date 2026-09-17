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

"""What a command handler is given, and what it is expected to give back."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any, List, Optional

from mcpscanner.core.models import AnalyzerEnum


@dataclass
class CommandContext:
    """Everything a command handler needs from the invocation.

    ``analyzers`` is mutable on purpose: ``vulnerable-package`` narrows the
    selection after it runs, and the report header has to reflect that.
    """

    args: argparse.Namespace
    analyzers: List[AnalyzerEnum]


#: What a handler returns: the scan results to report, or ``None`` when it
#: has already written its own output and rendering should be skipped.
CommandResult = Optional[Any]
