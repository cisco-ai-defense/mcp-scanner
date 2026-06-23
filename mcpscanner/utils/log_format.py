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

"""Shared helpers for structured ``key=value`` operator logs."""

from __future__ import annotations

import re

ERROR_TRUNCATE: int = 400
RESPONSE_DEBUG_MAX: int = 500

_LOG_VALUE_SCRUB = re.compile(r"[\s=\"'`]")


def truncate(value: object, limit: int = ERROR_TRUNCATE) -> str:
    """Stringify ``value`` and clip to ``limit`` chars with a ``…(+N)`` marker."""
    s = str(value)
    if len(s) <= limit:
        return s
    return f"{s[:limit]}…(+{len(s) - limit})"


def sanitize_log_value(value: object) -> str:
    """Replace whitespace, ``=``, and quotes in ``value`` with ``_``.

    ``None`` and the empty string become the sentinel ``"-"`` so the
    resulting log line still has a non-empty value for parsers like
    Splunk's ``KV_MODE``. Numeric / boolean falsy values (``0``,
    ``False``) are rendered verbatim — only string-like emptiness is
    collapsed.
    """
    if value is None:
        return "-"
    s = str(value)
    if not s:
        return "-"
    return _LOG_VALUE_SCRUB.sub("_", s)


__all__ = [
    "ERROR_TRUNCATE",
    "RESPONSE_DEBUG_MAX",
    "truncate",
    "sanitize_log_value",
]
