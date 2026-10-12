# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Deferred access to ``litellm``.

Importing ``litellm`` pulls in ~1700 extra modules (openai, tokenizers,
httpx internals, ...) and dominates process startup. Analyzer modules
only need it when a request is actually issued, but a module-level
``from litellm import acompletion`` makes every importer of
``mcpscanner`` pay that cost up front --- including ``mcp-scanner --help``
and the subcommands that never call an LLM.

This module exposes a thin passthrough that imports ``litellm`` on first
*call* instead of at import time. Analyzer modules do::

    from ...utils.lazy_litellm import acompletion

and keep calling ``await acompletion(...)`` unchanged.

``acompletion`` is deliberately declared with ``async def`` rather than a
plain ``def`` that returns litellm's coroutine. ``unittest.mock.patch``
chooses its replacement class by calling
:func:`asyncio.iscoroutinefunction` on the target: a coroutine function
is replaced with :class:`~unittest.mock.AsyncMock`, anything else with a
:class:`~unittest.mock.MagicMock` whose return value cannot be awaited.
The existing suite patches these names in bare form
(``@patch("...llm_analyzer.acompletion")``) and then awaits the call, so a
plain ``def`` here breaks those tests with "object MagicMock can't be
used in 'await' expression". Keep this an ``async def``.
"""

from importlib import import_module, util
from typing import Any, Optional

__all__ = ["acompletion", "is_litellm_available", "litellm_import_error"]


async def acompletion(*args: Any, **kwargs: Any) -> Any:
    """Await ``litellm.acompletion``, importing ``litellm`` on first use.

    Args:
        *args: Positional arguments forwarded verbatim to ``litellm.acompletion``.
        **kwargs: Keyword arguments forwarded verbatim to ``litellm.acompletion``.

    Returns:
        Whatever ``litellm.acompletion`` resolves to.
    """
    return await import_module("litellm").acompletion(*args, **kwargs)


def is_litellm_available() -> bool:
    """Return whether ``litellm`` can be imported, without importing it.

    Uses :func:`importlib.util.find_spec`, which locates the module
    without executing it, so an availability probe stays cheap.
    """
    try:
        return util.find_spec("litellm") is not None
    except (ImportError, ValueError):
        return False


def litellm_import_error() -> Optional[str]:
    """Return a human-readable reason ``litellm`` is unavailable, else ``None``."""
    if is_litellm_available():
        return None
    return "No module named 'litellm'"
