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

"""Alignment Orchestrator - Main Coordinator.

This module provides the main orchestrator for semantic alignment verification.
It coordinates the alignment verification process by:
1. Building comprehensive prompts with evidence
2. Querying LLM for alignment verification
3. Validating and parsing responses
4. Creating security findings for mismatches

This is the entry point for all alignment verification operations.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .....config.config import Config
from .....threats.threats import ThreatMapping
from .....utils.log_format import sanitize_log_value, truncate
from ....static_analysis.context_extractor import FunctionContext
from .alignment_prompt_builder import AlignmentPromptBuilder
from .alignment_llm_client import AlignmentLLMClient
from .alignment_response_validator import AlignmentResponseValidator, is_unanalysed
from .threat_vulnerability_classifier import ThreatVulnerabilityClassifier


class AlignmentOrchestrator:
    """Orchestrates semantic alignment verification between docstrings and code.

    This is the main alignment verification layer that coordinates:
    - Prompt building with comprehensive evidence
    - LLM-based alignment verification
    - Response validation and finding creation

    This class provides a clean interface for alignment checking and hides
    the complexity of prompt construction, LLM interaction, and parsing.
    """

    def __init__(self, config: Config):
        """Initialize alignment orchestrator.

        Args:
            config: Configuration with LLM credentials

        Raises:
            ValueError: If LLM configuration is missing
        """
        self.logger = logging.getLogger(__name__)

        # Initialize alignment verification components
        self.prompt_builder = AlignmentPromptBuilder()
        self.llm_client = AlignmentLLMClient(config)
        self.response_validator = AlignmentResponseValidator()
        self.threat_vuln_classifier = ThreatVulnerabilityClassifier(config)

        self.stats = self._fresh_stats()
        # Names of functions whose alignment check raised or produced an
        # invalid response in the current scan. Consumed by the behavioural
        # analyzer to skip SAFE-synthesis (an errored function is not
        # "safe", just unknown).
        self.errored_function_names: Set[str] = set()

        self.logger.debug("AlignmentOrchestrator initialized")

    @staticmethod
    def _fresh_stats() -> Dict[str, int]:
        """Return a fresh, zeroed stats dict."""
        return {
            "total_analyzed": 0,
            "mismatches_detected": 0,
            "no_mismatch": 0,
            "skipped_invalid_response": 0,
            "skipped_error": 0,
        }

    def reset_stats(self) -> None:
        """Reset cumulative counters to zero."""
        for key in self.stats:
            self.stats[key] = 0
        self.errored_function_names.clear()

    async def check_alignment(
        self, func_context: FunctionContext
    ) -> Optional[Tuple[Dict[str, Any], FunctionContext]]:
        """Check if function behavior aligns with its docstring.

        This is the main entry point for alignment verification. It coordinates
        the full verification pipeline:
        1. Build comprehensive prompt with evidence
        2. Query LLM for alignment analysis
        3. Validate response
        4. Return analysis and context for SecurityFinding creation

        Args:
            func_context: Complete function context with dataflow analysis

        Returns:
            Tuple of (analysis_dict, func_context) if mismatch detected, None if aligned
        """
        self.stats["total_analyzed"] += 1
        check_start = time.perf_counter()

        try:
            # Step 1: Build alignment verification prompt
            self.logger.debug(f"Building alignment prompt for {func_context.name}")
            try:
                prompt = self.prompt_builder.build_prompt(func_context)
            except Exception as e:
                self.logger.error(
                    f"Prompt building failed for {func_context.name}: {e}",
                    exc_info=True,
                )
                raise

            # Step 2: Query LLM for alignment verification
            self.logger.debug(
                f"Querying LLM for alignment verification of {func_context.name}"
            )
            try:
                response = await self.llm_client.verify_alignment(prompt)
            except Exception as e:
                self.logger.error(
                    f"LLM verification failed for {func_context.name}: {e}",
                    exc_info=True,
                )
                raise

            # Step 3: Validate and parse response
            self.logger.debug(f"Validating alignment response for {func_context.name}")
            try:
                result = self.response_validator.validate(response)
            except Exception as e:
                self.logger.error(
                    f"Response validation failed for {func_context.name}: {e}",
                    exc_info=True,
                )
                raise

            if not result:
                self.logger.warning(
                    f"Invalid response for {func_context.name}, skipping"
                )
                self.stats["skipped_invalid_response"] += 1
                name = getattr(func_context, "name", None)
                if name:
                    self.errored_function_names.add(name)
                return None

            # Step 4: Return analysis if mismatch detected
            if result.get("mismatch_detected"):
                check_ms = int((time.perf_counter() - check_start) * 1000)
                self.logger.info(
                    "alignment mismatch function=%s threat=%s duration_ms=%d",
                    func_context.name,
                    result.get("threat_name", "<unset>") or "<unset>",
                    check_ms,
                )
                self.stats["mismatches_detected"] += 1

                # Step 5: Classify as threat or vulnerability (second alignment layer)
                # Skip classification for INFO severity (documentation issues)
                threat_name = result.get("threat_name", "")
                if threat_name != "GENERAL DESCRIPTION-CODE MISMATCH":
                    self.logger.debug(
                        f"Classifying finding as threat or vulnerability for {func_context.name}"
                    )
                    try:
                        mapped_severity = self._get_mapped_severity(threat_name)
                        classification = (
                            await self.threat_vuln_classifier.classify_finding(
                                threat_name=threat_name or "UNKNOWN",
                                severity=mapped_severity,
                                summary=result.get("summary", ""),
                                description_claims=result.get("description_claims", ""),
                                actual_behavior=result.get("actual_behavior", ""),
                                security_implications=result.get(
                                    "security_implications", ""
                                ),
                                dataflow_evidence=result.get("dataflow_evidence", ""),
                            )
                        )
                        if classification:
                            # Add just the classification value to the result
                            result["threat_vulnerability_classification"] = (
                                classification["classification"]
                            )
                            self.logger.debug(
                                f"Classified as {classification['classification']} with {classification['confidence']} confidence"
                            )
                        else:
                            self.logger.warning(
                                f"Failed to classify finding for {func_context.name}"
                            )
                            result["threat_vulnerability_classification"] = "UNCLEAR"
                    except Exception as e:
                        self.logger.error(
                            f"Classification failed for {func_context.name}: {e}",
                            exc_info=True,
                        )
                        # Continue without classification - mark as UNCLEAR
                        result["threat_vulnerability_classification"] = "UNCLEAR"

                return (result, func_context)
            else:
                check_ms = int((time.perf_counter() - check_start) * 1000)
                self.logger.debug(
                    "alignment ok function=%s duration_ms=%d",
                    func_context.name,
                    check_ms,
                )
                self.stats["no_mismatch"] += 1
                return None

        except Exception as e:
            check_ms = int((time.perf_counter() - check_start) * 1000)
            self.logger.error(
                "alignment check failed function=%s duration_ms=%d error_type=%s error=%s",
                func_context.name,
                check_ms,
                type(e).__name__,
                truncate(e),
            )
            self.stats["skipped_error"] += 1
            name = getattr(func_context, "name", None)
            if name:
                self.errored_function_names.add(name)
            return None

    async def check_alignment_batch(
        self, func_contexts: List[FunctionContext], batch_size: int = 5
    ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
        """Check alignment for multiple functions in batched LLM calls.

        This method batches multiple functions into single LLM requests to reduce
        API calls and improve scanning speed.

        Args:
            func_contexts: List of function contexts to analyze
            batch_size: Number of functions per LLM request (default: 5)

        Returns:
            List of (analysis_dict, func_context) tuples for detected mismatches
        """
        results = []

        total_funcs = len(func_contexts)
        total_batches = (total_funcs + batch_size - 1) // batch_size if batch_size else 0
        self.logger.info(
            "alignment batch scan start total_functions=%d batches=%d batch_size=%d",
            total_funcs,
            total_batches,
            batch_size,
        )

        # Process in batches
        for i in range(0, len(func_contexts), batch_size):
            batch = func_contexts[i:i + batch_size]
            batch_idx = i // batch_size + 1
            batch_start = time.perf_counter()
            self.logger.debug(
                "batch %d/%d start size=%d", batch_idx, total_batches, len(batch)
            )

            try:
                # Build batched prompt
                prompt = self.prompt_builder.build_batch_prompt(batch)

                # Query LLM
                response = await self.llm_client.verify_alignment(prompt)

                # Parse batched response
                batch_results = self.response_validator.validate_batch(response, len(batch))

                # ``None`` means hard failure (empty / unparseable response).
                # An empty *list* would mean the batch was empty, which is
                # impossible here because we only enter the loop when
                # ``len(batch) > 0``. Use ``is None`` for symmetry with the
                # validator's own contract.
                if batch_results is None:
                    self.logger.warning(
                        "batch %d/%d invalid_response fallback=individual size=%d "
                        "-- LLM returned an unparseable batch, retrying each function individually",
                        batch_idx,
                        total_batches,
                        len(batch),
                    )
                    for func_context in batch:
                        result = await self.check_alignment(func_context)
                        if result:
                            results.append(result)
                    continue
                
                # Process each result in the batch
                batch_mismatches = 0
                batch_clean = 0
                batch_unanalysed = 0
                for idx, result in enumerate(batch_results):
                    if idx >= len(batch):
                        break

                    func_context = batch[idx]
                    self.stats["total_analyzed"] += 1

                    # Sentinel slot: the LLM never produced a valid
                    # result for this function. Source taxonomy lives in
                    # ``alignment_response_validator._validate_items`` —
                    # short-padding, non-dict items, items missing
                    # ``mismatch_detected``, and malformed mismatches
                    # (``mismatch_detected=true`` without
                    # ``threat_name`` / ``summary``) all funnel through
                    # ``_unanalysed_sentinel()`` and end up here. Adversarial
                    # LLM-supplied ``_unanalysed`` keys are stripped by
                    # the validator, so reaching this branch means the
                    # *validator* tagged the slot. Route to errored —
                    # these functions are "unknown", not "safe".
                    if is_unanalysed(result):
                        self.stats["skipped_invalid_response"] += 1
                        batch_unanalysed += 1
                        name = getattr(func_context, "name", None)
                        if name:
                            self.errored_function_names.add(name)
                        continue

                    if result and result.get("mismatch_detected"):
                        self.stats["mismatches_detected"] += 1
                        batch_mismatches += 1
                        
                        # Classify as threat or vulnerability
                        threat_name = result.get("threat_name", "")
                        if threat_name != "GENERAL DESCRIPTION-CODE MISMATCH":
                            try:
                                mapped_severity = self._get_mapped_severity(threat_name)
                                classification = await self.threat_vuln_classifier.classify_finding(
                                    threat_name=threat_name or "UNKNOWN",
                                    severity=mapped_severity,
                                    summary=result.get("summary", ""),
                                    description_claims=result.get("description_claims", ""),
                                    actual_behavior=result.get("actual_behavior", ""),
                                    security_implications=result.get("security_implications", ""),
                                    dataflow_evidence=result.get("dataflow_evidence", ""),
                                )
                                if classification:
                                    result["threat_vulnerability_classification"] = classification["classification"]
                                else:
                                    result["threat_vulnerability_classification"] = "UNCLEAR"
                            except Exception as e:
                                self.logger.error(f"Classification failed: {e}")
                                result["threat_vulnerability_classification"] = "UNCLEAR"
                        
                        results.append((result, func_context))
                    else:
                        self.stats["no_mismatch"] += 1
                        batch_clean += 1

                batch_ms = int((time.perf_counter() - batch_start) * 1000)
                self.logger.info(
                    "batch %d/%d done size=%d mismatches=%d clean=%d "
                    "unanalysed=%d duration_ms=%d",
                    batch_idx,
                    total_batches,
                    len(batch),
                    batch_mismatches,
                    batch_clean,
                    batch_unanalysed,
                    batch_ms,
                )

            except Exception as e:
                batch_ms = int((time.perf_counter() - batch_start) * 1000)
                self.logger.error(
                    "batch %d/%d failed size=%d duration_ms=%d error_type=%s "
                    "error=%s fallback=individual_analysis",
                    batch_idx,
                    total_batches,
                    len(batch),
                    batch_ms,
                    type(e).__name__,
                    truncate(e),
                )
                # NOTE: we do *not* pre-populate ``errored_function_names``
                # for the whole batch. ``check_alignment`` is total — it
                # marks errored on raise / invalid-response, and leaves
                # the set untouched on clean / mismatch. Pre-marking
                # would mis-flag cleanly-retried functions as errored.
                for func_context in batch:
                    result = await self.check_alignment(func_context)
                    if result:
                        results.append(result)

        return results

    @staticmethod
    def _get_mapped_severity(threat_name: str) -> str:
        """Derive severity from centralized ThreatMapping.

        Args:
            threat_name: Threat name from the LLM result

        Returns:
            Mapped severity string, or "UNKNOWN" when the threat name is unrecognised.
        """
        if not threat_name:
            return "UNKNOWN"
        try:
            threat_info = ThreatMapping.get_threat_mapping(
                "behavioral", threat_name.upper()
            )
            return threat_info["severity"]
        except (ValueError, KeyError):
            return "UNKNOWN"

    def get_statistics(self) -> Dict[str, int]:
        """Get analysis statistics.

        The fields obey the partitioning invariant:

            total_analyzed == (
                mismatches_detected
                + no_mismatch
                + skipped_invalid_response
                + skipped_error
            )

        i.e. every function the orchestrator *attempted* to analyse falls
        into exactly one of the four outcome buckets. Operators reading
        these fields for SLO purposes should treat
        ``skipped_invalid_response + skipped_error`` as the "did not get
        a usable LLM result" bucket — those functions are surfaced as
        ``UNKNOWN`` severity downstream.

        Returns:
            Dictionary with analysis statistics including:
            - total_analyzed: Total functions analyzed (success + failure)
            - mismatches_detected: Functions with detected mismatches
            - no_mismatch: Functions with no mismatch
            - skipped_invalid_response: Functions skipped due to invalid LLM response
              (includes short-padded slots, malformed batch items, etc.)
            - skipped_error: Functions skipped due to exceptions
        """
        return self.stats.copy()

    def log_summary(self, scope: str = "behavioral") -> None:
        """Emit a single ``key=value`` INFO summary line for the current stats.

        Args:
            scope: Free-form label that distinguishes summaries when the
                orchestrator runs in more than one context. Sanitised
                before logging.
        """
        s = self.stats
        safe_scope = sanitize_log_value(scope)
        self.logger.info(
            "alignment summary scope=%s total=%d mismatches=%d clean=%d "
            "skipped_invalid_response=%d skipped_error=%d",
            safe_scope,
            s["total_analyzed"],
            s["mismatches_detected"],
            s["no_mismatch"],
            s["skipped_invalid_response"],
            s["skipped_error"],
        )
