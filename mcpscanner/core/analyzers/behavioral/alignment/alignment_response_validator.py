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
from ....static_analysis.context_extractor import FunctionContext
from .json_utils import parse_json_from_llm


class AlignmentResponseValidator:
    """Validates alignment verification responses from LLM.

    Ensures LLM responses are properly formatted JSON with required
    alignment check fields and converts them to SecurityFindings.
    """

    def __init__(self):
        """Initialize the alignment response validator."""
        self.logger = logging.getLogger(__name__)

    def validate(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse and validate alignment check response.

        Args:
            response: JSON response from LLM

        Returns:
            Parsed alignment check result or None if invalid
        """
        response_length = len(response) if response else 0
        if not response or not response.strip():
            # response_length tells operators whether the body was empty
            # or whitespace-only — useful for distinguishing a real
            # transport-level empty from a model that returned " ".
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

            # Check for required fields
            if not self._has_required_fields(data):
                # Sort + cap the key list so the log line is stable and
                # bounded — otherwise a hostile/large response could push
                # multi-KB key lists into the log stream.
                keys = sorted(data.keys())
                if len(keys) > 25:
                    keys = keys[:25] + ["...(truncated)"]
                self.logger.warning(
                    "validator missing_required_fields response_length=%d keys=%s",
                    response_length,
                    keys,
                )
                return None

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
                e,
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
            # Try to parse JSON
            data = json.loads(response)

            # Validate it's a list
            if not isinstance(data, list):
                self.logger.warning(
                    "validator batch not_a_json_array got_type=%s response_length=%d "
                    "expected_count=%d -- trying markdown fallback",
                    type(data).__name__,
                    response_length,
                    expected_count,
                )
                # Try to extract from markdown
                data = self._extract_json_array_from_markdown(response)
                if not data:
                    self.logger.warning(
                        "validator batch markdown_fallback_failed response_length=%d "
                        "expected_count=%d",
                        response_length,
                        expected_count,
                    )
                    return None

            # Validate each item in the array
            results = []
            invalid_items = 0
            padded_items = 0
            for idx, item in enumerate(data):
                if not isinstance(item, dict):
                    self.logger.warning(
                        "validator batch item_not_dict idx=%d got_type=%s",
                        idx,
                        type(item).__name__,
                    )
                    invalid_items += 1
                    results.append({"mismatch_detected": False})
                    continue

                # Check for required fields
                if "mismatch_detected" not in item:
                    # Default to no mismatch if field missing
                    self.logger.debug(
                        "validator batch item_missing_field idx=%d "
                        "field=mismatch_detected -- defaulting to False",
                        idx,
                    )
                    item["mismatch_detected"] = False
                    padded_items += 1

                results.append(item)

            # Pad with empty results if we got fewer than expected
            initial_len = len(results)
            while len(results) < expected_count:
                results.append({"mismatch_detected": False})
            short_padding = len(results) - initial_len
            if short_padding:
                self.logger.warning(
                    "validator batch truncated_response got=%d expected=%d padded=%d "
                    "-- LLM returned fewer items than batch size; downstream will "
                    "treat the padded slots as clean",
                    initial_len,
                    expected_count,
                    short_padding,
                )

            self.logger.debug(
                "validator batch ok response_length=%d results=%d invalid_items=%d "
                "padded_items=%d",
                response_length,
                len(results),
                invalid_items,
                padded_items,
            )
            return results

        except json.JSONDecodeError as e:
            self.logger.warning(
                "validator batch invalid_json response_length=%d expected_count=%d "
                "error=%s -- trying markdown fallback",
                response_length,
                expected_count,
                e,
            )
            # Try to extract JSON array from markdown
            return self._extract_json_array_from_markdown(response)
        except Exception as e:
            self.logger.error(
                "validator batch unexpected_error response_length=%d expected_count=%d "
                "error_type=%s error=%s",
                response_length,
                expected_count,
                type(e).__name__,
                e,
            )
            return None

    def _extract_json_array_from_markdown(self, response: str) -> Optional[List[Dict[str, Any]]]:
        """Try to extract JSON array from markdown code blocks.

        Args:
            response: Response that may contain markdown

        Returns:
            Parsed JSON array or None
        """
        try:
            # Look for ```json ... ``` or ``` ... ```
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                json_str = response[start:end].strip()
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                json_str = response[start:end].strip()
            else:
                return None

            data = json.loads(json_str)
            if isinstance(data, list):
                return data

        except Exception:
            pass

        return None
