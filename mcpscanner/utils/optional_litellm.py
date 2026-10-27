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

"""Optional LiteLLM import for LLM-backed analyzers.

YARA and the other non-LLM analyzers never import LiteLLM. The LLM, meta,
behavioral-alignment, and readiness judges do, and they are installed with
``pip install "cisco-ai-mcp-scanner[llm]"``.
"""

from __future__ import annotations

import sys
from typing import Any

LITELLM_EXTRA = "llm"
LITELLM_REQUIRED_MESSAGE = (
    "LiteLLM is required for the LLM analyzer. "
    'Install it with: pip install "cisco-ai-mcp-scanner[llm]"'
)


class LiteLLMNotInstalledError(ImportError, ValueError):
    """Raised when an LLM-backed analyzer is used and LiteLLM is not installed.

    Subclasses ``ValueError`` as well so existing configuration checks
    that catch ``ValueError`` still see it. Callers that need the HTTP
    status, or a dedicated handler, should match this type rather than
    the wording of the message.
    """


def _is_missing_litellm_package(exc: BaseException) -> bool:
    """True when the top-level ``litellm`` distribution itself is absent.

    A missing dependency of an installed LiteLLM is a different failure and
    must not be reported as "install the extra".
    """
    return isinstance(exc, ModuleNotFoundError) and exc.name == "litellm"


def litellm_importable() -> bool:
    """Return whether the ``litellm`` module can be imported.

    A ``None`` entry in ``sys.modules`` is treated as missing. That is the
    same stand-in used to prove a YARA-only import does not need LiteLLM.
    An ``ImportError`` from a dependency of an installed LiteLLM is re-raised.
    """
    if sys.modules.get("litellm", "missing") is None:
        return False
    try:
        import litellm
    except ImportError as exc:
        if _is_missing_litellm_package(exc):
            return False
        raise
    return litellm is not None


def require_acompletion() -> Any:
    """Return ``litellm.acompletion`` or raise an error that names the extra.

    Only a missing top-level ``litellm`` package becomes
    ``LiteLLMNotInstalledError``. Failures inside an installed LiteLLM
    propagate unchanged.
    """
    try:
        from litellm import acompletion
    except ImportError as exc:
        if not _is_missing_litellm_package(exc):
            raise
        raise LiteLLMNotInstalledError(LITELLM_REQUIRED_MESSAGE) from exc
    if acompletion is None:
        raise LiteLLMNotInstalledError(LITELLM_REQUIRED_MESSAGE)
    return acompletion
