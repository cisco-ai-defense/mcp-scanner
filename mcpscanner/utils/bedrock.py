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

"""Shared helpers for AWS Bedrock LLM support.

Bedrock is reached through litellm, which signs requests with AWS SigV4 using
``boto3``. ``boto3`` is an optional dependency (installed via the ``bedrock``
extra) so non-Bedrock users are not forced to pull in the AWS SDK. These
helpers centralise the "is this a Bedrock model?" check and a fail-fast
pre-flight that surfaces a clear, actionable error when ``boto3`` is missing
instead of litellm's opaque ``No module named 'boto3'`` at request time.
"""

import importlib.util


class BedrockDependencyError(ImportError):
    """Raised when a Bedrock model is configured but ``boto3`` is not installed."""


def is_bedrock_model(model: str | None) -> bool:
    """Return ``True`` when ``model`` is a litellm ``bedrock/*`` model id."""
    return bool(model and "bedrock/" in model)


def ensure_bedrock_dependencies(model: str | None) -> None:
    """Validate that Bedrock runtime dependencies are importable.

    litellm requires ``boto3`` to authenticate ``bedrock/*`` models regardless
    of whether credentials come from a Bedrock API key, an
    ``AWS_BEARER_TOKEN_BEDROCK`` bearer token, or the standard AWS credential
    chain (IAM role / SSO / profile / session token).

    Args:
        model: The configured litellm model id.

    Raises:
        BedrockDependencyError: If ``model`` is a Bedrock model but ``boto3``
            cannot be imported.
    """
    if not is_bedrock_model(model):
        return
    if importlib.util.find_spec("boto3") is None:
        raise BedrockDependencyError(
            "boto3 is required to use AWS Bedrock models "
            f"('{model}') but is not installed. Install it with "
            "'pip install \"cisco-ai-mcp-scanner[bedrock]\"' (or 'pip install boto3')."
        )
