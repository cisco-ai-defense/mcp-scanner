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

"""Alignment Response Validator for Semantic Verification.

This module validates and parses LLM responses from semantic alignment verification queries.

The validator:
- Parses JSON responses from LLM
- Validates response schema and required fields
- Creates SecurityFinding objects for mismatches
- Handles parsing errors gracefully
"""

import json
import logging
from typing import Any, Dict, List, Optional

from ...base import SecurityFinding
from .....threats.threats import ThreatMapping
from .....utils.log_format import truncate
from ....static_analysis.context_extractor import FunctionContext
from .json_utils import parse_json_from_llm


# Internal sentinel key used on per-item batch results to signal that
# the LLM did *not* successfully analyse the corresponding function
# (short-padding, non-dict item, missing field, or malformed mismatch).
# The orchestrator routes any slot carrying this key to
# ``errored_function_names`` instead of ``no_mismatch``.
#
# It MUST NOT survive on an LLM-supplied dict: a model could otherwise
# coerce its own clean responses into the "errored" bucket simply by
# emitting ``"_unanalysed": true``. ``validate()`` and ``_validate_items``
# both strip this key from every passthrough item via
# :func:`_strip_unanalysed`.
#
# Cross-module callers should prefer :func:`is_unanalysed` over reading
# the raw key so we can swap implementations later without churning
# every consumer.
_UNANALYSED_KEY = "_unanalysed"


def _unanalysed_sentinel() -> Dict[str, Any]:
    """Return a fresh per-slot sentinel marking a non-analysed function."""
    return {"mismatch_detected": False, _UNANALYSED_KEY: True}


def is_unanalysed(result: Any) -> bool:
    """Return True iff ``result`` is a sentinel from
    :func:`_unanalysed_sentinel` (or otherwise carries the internal
    sentinel key). Safe to call on arbitrary objects."""
    return isinstance(result, dict) and bool(result.get(_UNANALYSED_KEY))


class AlignmentResponseValidator:
    """Validates alignment verification responses from LLM.

    Ensures LLM responses are properly formatted JSON with required
    alignment check fields and converts them to SecurityFindings.
    """

    def __init__(self):
        """Initialize the alignment response validator."""
        self.logger = logging.getLogger(__name__)

    def _strip_unanalysed(
        self, item: Dict[str, Any], *, context: str, idx: int = -1
    ) -> Dict[str, Any]:
        """Return ``item`` with any adversarial ``_unanalysed`` key
        removed. Per-call site emits a DEBUG breadcrumb; aggregation
        into one WARNING is the caller's responsibility.

        Args:
            item: LLM-supplied dict (mutated copy returned; original
                is never modified).
            context: Free-form label for log breadcrumbs (e.g.
                ``"single"`` or ``"batch"``).
            idx: Batch index, or ``-1`` for single-shot.

        Returns:
            ``item`` unchanged if the sentinel is absent, else a fresh
            dict with the sentinel removed.
        """
        if _UNANALYSED_KEY not in item:
            return item
        self.logger.debug(
            "validator %s llm_supplied_sentinel idx=%d -- stripping '%s'",
            context,
            idx,
            _UNANALYSED_KEY,
        )
        return {k: v for k, v in item.items() if k != _UNANALYSED_KEY}

    def validate(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse and validate alignment check response.

        Args:
            response: JSON response from LLM

        Returns:
            Parsed alignment check result or None if invalid
        """
        response_length = len(response) if response else 0
        if not response or not response.strip():
            self.logger.warning(
                "validator empty_response response_length=%d", response_length
            )
            return None

        try:
            data = parse_json_from_llm(response)

            if data is None:
                self.logger.warning(
                    "validator invalid_json response_length=%d", response_length
                )
                self.logger.debug(
                    "validator raw_response_prefix=%r", response[:500]
                )
                return None

            # Validate it's a dictionary
            if not isinstance(data, dict):
                self.logger.warning(
                    "validator not_a_json_object response_length=%d got_type=%s",
                    response_length,
                    type(data).__name__,
                )
                return None

            if not self._has_required_fields(data):
                keys = sorted(data.keys())
                if len(keys) > 25:
                    keys = keys[:25] + ["...(truncated)"]
                self.logger.warning(
                    "validator missing_required_fields response_length=%d keys=%s",
                    response_length,
                    keys,
                )
                return None

            # Defence in depth: the LLM must not be able to inject our
            # private sentinel into a single-shot result. Same rule
            # applies in ``_validate_items``.
            stripped = _UNANALYSED_KEY in data
            data = self._strip_unanalysed(data, context="single")
            if stripped:
                self.logger.warning(
                    "validator single llm_supplied_sentinel stripped=1 "
                    "-- adversarial '%s' key removed from single-shot result",
                    _UNANALYSED_KEY,
                )

            self.logger.debug(
                "validator ok response_length=%d mismatch_detected=%s threat_name=%s",
                response_length,
                data.get("mismatch_detected"),
                data.get("threat_name", "<unset>"),
            )
            return data

        except Exception as e:
            self.logger.error(
                "validator unexpected_error response_length=%d error_type=%s error=%s",
                response_length,
                type(e).__name__,
                truncate(e),
            )
            return None

    def _has_required_fields(self, data: Dict[str, Any]) -> bool:
        """Check if response has all required alignment check fields.

        Args:
            data: Parsed JSON response

        Returns:
            True if all required fields present
        """
        required_fields = ["mismatch_detected"]

        # Check required fields
        if not all(field in data for field in required_fields):
            return False

        # If mismatch detected, check for additional required fields
        # Note: severity is no longer required from LLM - it's determined by threat classification system
        # threat_name is required because downstream uses it to map severity and taxonomy
        if data.get("mismatch_detected"):
            mismatch_required = ["threat_name", "summary"]
            if not all(field in data for field in mismatch_required):
                return False

        return True

    def create_security_finding(
        self, analysis: Dict[str, Any], func_context: FunctionContext
    ) -> SecurityFinding:
        """Create SecurityFinding from alignment check result.

        Args:
            analysis: Validated alignment check result from LLM
            func_context: Function context that was analyzed

        Returns:
            SecurityFinding object
        """
        # Use severity from centralized threat mapping only
        threat_name = analysis.get("threat_name", "").upper()
        try:
            threat_info = ThreatMapping.get_threat_mapping("behavioral", threat_name)
            severity = threat_info["severity"]
        except (ValueError, KeyError):
            severity = "UNKNOWN"

        # Format threat summary to show comparison: Claims vs Reality
        description_claims = analysis.get("description_claims", "")
        actual_behavior = analysis.get("actual_behavior", "")

        # Include line number in the summary for easy reference
        line_info = f"Line {func_context.line_number}: "

        if description_claims and actual_behavior:
            threat_summary = f"{line_info}Description claims: '{description_claims}' | Actual behavior: {actual_behavior}"
        else:
            # Fallback to security implications if comparison fields are missing
            threat_summary = f"{line_info}{analysis.get('security_implications', f'Mismatch detected in {func_context.name}')}"

        # If summary provided directly, use that
        if "summary" in analysis:
            threat_summary = f"{line_info}{analysis['summary']}"

        finding = SecurityFinding(
            severity=severity,
            summary=threat_summary,
            analyzer="Behavioural",
            threat_category="DESCRIPTION_MISMATCH",
            details={
                "function_name": func_context.name,
                "decorator_type": (
                    func_context.decorator_types[0]
                    if func_context.decorator_types
                    else "unknown"
                ),
                "line_number": func_context.line_number,
                "mismatch_type": analysis.get("mismatch_type"),
                "description_claims": description_claims,
                "actual_behavior": actual_behavior,
                "security_implications": analysis.get("security_implications"),
                "confidence": analysis.get("confidence"),
                "dataflow_evidence": analysis.get("dataflow_evidence"),
                "parameter_flows": func_context.parameter_flows,
            },
        )

        return finding

    def validate_batch(self, response: str, expected_count: int) -> Optional[List[Dict[str, Any]]]:
        """Parse and validate batched alignment check response.

        Args:
            response: JSON array response from LLM
            expected_count: Expected number of function results

        Returns:
            List of parsed alignment check results or None if invalid
        """
        response_length = len(response) if response else 0
        if not response or not response.strip():
            self.logger.warning(
                "validator batch empty_response response_length=%d expected_count=%d",
                response_length,
                expected_count,
            )
            return None

        try:
            data = json.loads(response)

            if not isinstance(data, list):
                self.logger.warning(
                    "validator batch not_a_json_array got_type=%s response_length=%d "
                    "expected_count=%d -- trying markdown fallback",
                    type(data).__name__,
                    response_length,
                    expected_count,
                )
                data = self._extract_json_array_from_markdown(response)
                if data is None:
                    self.logger.warning(
                        "validator batch markdown_fallback_failed response_length=%d "
                        "expected_count=%d",
                        response_length,
                        expected_count,
                    )
                    return None

        except json.JSONDecodeError as e:
            self.logger.warning(
                "validator batch invalid_json response_length=%d expected_count=%d "
                "error=%s -- trying markdown fallback",
                response_length,
                expected_count,
                truncate(e),
            )
            data = self._extract_json_array_from_markdown(response)
            if data is None:
                self.logger.warning(
                    "validator batch markdown_fallback_failed response_length=%d "
                    "expected_count=%d",
                    response_length,
                    expected_count,
                )
                return None
        except Exception as e:
            self.logger.error(
                "validator batch unexpected_error response_length=%d expected_count=%d "
                "error_type=%s error=%s",
                response_length,
                expected_count,
                type(e).__name__,
                truncate(e),
            )
            return None

        return self._validate_items(data, expected_count, response_length)

    def _validate_items(
        self,
        data: List[Any],
        expected_count: int,
        response_length: int,
    ) -> List[Dict[str, Any]]:
        """Coerce ``data`` into a list of well-shaped per-function result dicts.

        Each returned slot is one of:

        * a real, well-formed result dict from the LLM (with any
          adversarial ``_unanalysed`` key stripped), or
        * the :func:`_unanalysed_sentinel` dict — when the LLM returned a
          non-dict, an item missing ``mismatch_detected``, an item
          claiming a mismatch without the required ``threat_name`` /
          ``summary`` fields, or simply fewer items than
          ``expected_count``.

        The orchestrator routes every ``_unanalysed`` slot to
        ``errored_function_names`` so callers don't mis-label
        never-analysed functions as clean.
        """
        results: List[Dict[str, Any]] = []
        invalid_items = 0
        stripped_sentinels = 0
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                self.logger.warning(
                    "validator batch item_not_dict idx=%d got_type=%s",
                    idx,
                    type(item).__name__,
                )
                invalid_items += 1
                results.append(_unanalysed_sentinel())
                continue

            if "mismatch_detected" not in item:
                self.logger.warning(
                    "validator batch item_missing_field idx=%d "
                    "field=mismatch_detected -- routing to errored",
                    idx,
                )
                invalid_items += 1
                results.append(_unanalysed_sentinel())
                continue

            # If the item claims a mismatch, ``threat_name`` and ``summary``
            # must both be present — otherwise downstream classification
            # silently drops the finding, producing no output at all for
            # the function. Mirror what ``validate()`` enforces for the
            # single-item path.
            if item.get("mismatch_detected"):
                missing = [
                    field for field in ("threat_name", "summary")
                    if field not in item
                ]
                if missing:
                    self.logger.warning(
                        "validator batch mismatch_missing_fields idx=%d "
                        "fields=%s -- routing to errored",
                        idx,
                        ",".join(missing),
                    )
                    invalid_items += 1
                    results.append(_unanalysed_sentinel())
                    continue

            # Defence in depth: strip any adversarial ``_unanalysed``
            # key from LLM-supplied dicts. Per-item DEBUG breadcrumbs
            # come from the helper; we aggregate into one WARNING
            # below to keep logs sane under adversarial input.
            if _UNANALYSED_KEY in item:
                stripped_sentinels += 1
                item = self._strip_unanalysed(item, context="batch", idx=idx)

            results.append(item)

        if stripped_sentinels:
            self.logger.warning(
                "validator batch llm_supplied_sentinel stripped=%d "
                "-- adversarial '%s' keys removed; see DEBUG for per-item idx",
                stripped_sentinels,
                _UNANALYSED_KEY,
            )

        initial_len = len(results)
        while len(results) < expected_count:
            # Tag short-padding slots so the orchestrator can route them
            # to ``errored_function_names`` rather than ``no_mismatch``
            # (a function the LLM never analysed is not "safe").
            results.append(_unanalysed_sentinel())
        short_padding = len(results) - initial_len
        if short_padding:
            self.logger.warning(
                "validator batch truncated_response got=%d expected=%d padded=%d "
                "-- LLM returned fewer items than batch size; the orchestrator "
                "will route the padded slots to errored/unknown",
                initial_len,
                expected_count,
                short_padding,
            )

        self.logger.debug(
            "validator batch ok response_length=%d results=%d invalid_items=%d "
            "short_padding=%d",
            response_length,
            len(results),
            invalid_items,
            short_padding,
        )
        return results

    def _extract_json_array_from_markdown(self, response: str) -> Optional[List[Dict[str, Any]]]:
        """Try to extract JSON array from markdown code blocks.

        Args:
            response: Response that may contain markdown

        Returns:
            Parsed JSON array or None
        """
        try:
            if "```json" in response:
                start = response.find("```json") + 7
            elif "```" in response:
                start = response.find("```") + 3
            else:
                self.logger.debug(
                    "validator batch markdown no_fence_found response_length=%d",
                    len(response) if response else 0,
                )
                return None

            end = response.find("```", start)
            # A missing closing fence is common when the LLM is truncated
            # mid-response. Slice through end-of-string instead of relying
            # on the ``[start:-1]`` quirk of ``str.find`` returning ``-1``.
            if end == -1:
                json_str = response[start:].strip()
            else:
                json_str = response[start:end].strip()

            data = json.loads(json_str)
            if isinstance(data, list):
                return data
            self.logger.debug(
                "validator batch markdown not_a_list got_type=%s",
                type(data).__name__,
            )

        except Exception as e:
            self.logger.debug(
                "validator batch markdown parse_failed error_type=%s error=%s",
                type(e).__name__,
                truncate(e),
            )

        return None
