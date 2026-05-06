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

import asyncio
import logging
import random
from typing import Any, Dict, List, Optional, Tuple

from .....config.config import Config
from .....threats.threats import ThreatMapping
from ....static_analysis.context_extractor import FunctionContext
from .alignment_prompt_builder import AlignmentPromptBuilder
from .alignment_llm_client import AlignmentLLMClient
from .alignment_response_validator import AlignmentResponseValidator
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

        # Track analysis statistics
        self.stats = {
            "total_analyzed": 0,
            "mismatches_detected": 0,
            "no_mismatch": 0,
            "skipped_invalid_response": 0,
            "skipped_error": 0,
        }

        self.logger.debug("AlignmentOrchestrator initialized")

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
                self.stats["skipped_error"] += 1
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
                self.stats["skipped_error"] += 1
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
                self.stats["skipped_error"] += 1
                raise

            if not result:
                self.logger.warning(
                    f"Invalid response for {func_context.name}, skipping"
                )
                self.stats["skipped_invalid_response"] += 1
                return None

            # Step 4: Return analysis if mismatch detected
            if result.get("mismatch_detected"):
                self.logger.debug(f"Alignment mismatch detected in {func_context.name}")
                self.stats["mismatches_detected"] += 1

                # Step 5: Classify as threat or vulnerability (second alignment
                # layer). Delegated to ``_classify_finding_safe`` so the
                # single-function and batch paths share identical
                # error/success behavior. Sets
                # ``result["threat_vulnerability_classification"]`` in place.
                self.logger.debug(
                    f"Classifying finding as threat or vulnerability for {func_context.name}"
                )
                await self._classify_finding_safe(result, func_context.name)
                return (result, func_context)
            else:
                self.logger.debug(f"No alignment mismatch in {func_context.name}")
                self.stats["no_mismatch"] += 1
                return None

        except Exception as e:
            self.logger.error(f"Alignment check failed for {func_context.name}: {e}")
            self.stats["skipped_error"] += 1
            return None

    async def _classify_finding_safe(
        self, result: Dict[str, Any], func_name: str
    ) -> Dict[str, Any]:
        """Run threat/vulnerability classification for a single finding.

        Wraps ``ThreatVulnerabilityClassifier.classify_finding`` so its result
        can be safely awaited inside an ``asyncio.gather`` without losing the
        per-finding error handling that the original sequential code provided.
        Sets ``result["threat_vulnerability_classification"]`` in-place to the
        classifier output, ``"UNCLEAR"`` on classifier error, or leaves it
        unset for ``GENERAL DESCRIPTION-CODE MISMATCH`` findings (which the
        existing pipeline intentionally skips).
        """
        threat_name = result.get("threat_name", "")
        if threat_name == "GENERAL DESCRIPTION-CODE MISMATCH":
            return result
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
                result["threat_vulnerability_classification"] = classification[
                    "classification"
                ]
            else:
                self.logger.warning(
                    f"Failed to classify finding for {func_name}"
                )
                result["threat_vulnerability_classification"] = "UNCLEAR"
        except Exception as e:
            self.logger.error(
                f"Classification failed for {func_name}: {e}", exc_info=True
            )
            result["threat_vulnerability_classification"] = "UNCLEAR"
        return result

    async def _process_one_batch(
        self,
        batch: List[FunctionContext],
        batch_index: int,
        max_retries: int,
    ) -> Optional[List[Optional[Dict[str, Any]]]]:
        """Run a single batch through the LLM with bounded retries.

        Returns the parsed per-function results from
        ``AlignmentResponseValidator.validate_batch`` on success. Returns
        ``None`` to signal that the caller should fall back to per-function
        analysis for this batch (either because every retry produced an
        unparseable response, or because the LLM call itself raised after
        the underlying client's own retry budget was exhausted).

        Note: the LLM client (``AlignmentLLMClient.verify_alignment``) already
        retries transient HTTP errors with exponential backoff, so retries
        here are specifically for *parseable* failures (empty/malformed JSON
        from the model) where re-prompting often succeeds.
        """
        attempts = max(1, max_retries + 1)
        for attempt in range(attempts):
            try:
                prompt = self.prompt_builder.build_batch_prompt(batch)
                response = await self.llm_client.verify_alignment(prompt)
                batch_results = self.response_validator.validate_batch(
                    response, len(batch)
                )
                if batch_results:
                    if attempt > 0:
                        self.logger.info(
                            f"Batch {batch_index} succeeded on retry {attempt}"
                        )
                    return batch_results

                if attempt < attempts - 1:
                    delay = (2**attempt) + random.uniform(0, 0.25)
                    self.logger.warning(
                        f"Batch {batch_index} returned an invalid/empty response "
                        f"(attempt {attempt + 1}/{attempts}); retrying in "
                        f"{delay:.2f}s"
                    )
                    await asyncio.sleep(delay)
                    continue

                self.logger.warning(
                    f"Batch {batch_index} produced unparseable responses "
                    f"after {attempts} attempt(s); falling back to "
                    f"per-function analysis"
                )
                return None

            except Exception as e:
                # The LLM client has already retried network errors; treat any
                # exception that escapes it as a hard failure for this batch
                # and let the caller fall back. We don't double-retry to
                # avoid amplifying load against an already-struggling endpoint.
                self.logger.error(
                    f"Batch {batch_index} LLM call failed after client-side "
                    f"retries: {e}; falling back to per-function analysis"
                )
                return None

        return None

    async def check_alignment_batch(
        self,
        func_contexts: List[FunctionContext],
        batch_size: int = 5,
        *,
        batch_concurrency: int = 4,
        batch_retries: int = 1,
    ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
        """Check alignment for multiple functions using parallel batched LLM calls.

        This method splits ``func_contexts`` into batches of ``batch_size`` and
        dispatches them to the LLM concurrently, bounded by an
        ``asyncio.Semaphore(batch_concurrency)`` so we never exceed the
        provider's rate limits. For each batch:

        1. Issue the batched prompt; if the response is unparseable, retry
           the *whole* batch up to ``batch_retries`` times with exponential
           backoff and jitter.
        2. If the batch ultimately fails, fall back to per-function analysis
           via ``check_alignment`` (also dispatched concurrently within the
           same semaphore).
        3. For batches that succeed, threat/vulnerability classification for
           each detected mismatch is dispatched in parallel via
           ``asyncio.gather`` rather than sequentially per finding.

        Args:
            func_contexts: List of function contexts to analyze.
            batch_size: Number of functions per LLM request (default: 5).
            batch_concurrency: Maximum number of batches in flight at once
                (default: 4). Lower this if you hit provider rate limits.
            batch_retries: Number of additional retries for parseable
                failures before falling back to per-function analysis
                (default: 1; 0 disables the parseable-failure retry).

        Returns:
            List of (analysis_dict, func_context) tuples for every detected
            mismatch (order is not guaranteed to match input order, since
            batches return as the LLM completes them; use details inside the
            tuple to attribute findings).
        """
        if not func_contexts:
            return []

        batches: List[List[FunctionContext]] = [
            func_contexts[i : i + batch_size]
            for i in range(0, len(func_contexts), batch_size)
        ]
        sem = asyncio.Semaphore(max(1, int(batch_concurrency or 1)))

        async def _run_batch(
            batch_index: int, batch: List[FunctionContext]
        ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
            async with sem:
                self.logger.debug(
                    f"Processing batch {batch_index} of {len(batch)} functions"
                )
                batch_results = await self._process_one_batch(
                    batch, batch_index, max_retries=batch_retries
                )

                if batch_results is None:
                    # Fall back to per-function analysis. Run the per-function
                    # checks concurrently *within* the same semaphore slot so
                    # we don't blow past batch_concurrency on the LLM side.
                    fallback_coros = [
                        self.check_alignment(fc) for fc in batch
                    ]
                    fallback_results = await asyncio.gather(
                        *fallback_coros, return_exceptions=True
                    )
                    return [
                        r
                        for r in fallback_results
                        if r is not None and not isinstance(r, BaseException)
                    ]

                # Collect mismatches and dispatch their classifications in
                # parallel so a noisy file doesn't pay sum-of-classifications
                # latency on top of the batched LLM call.
                mismatches: List[Tuple[Dict[str, Any], FunctionContext]] = []
                classification_coros = []
                for idx, result in enumerate(batch_results):
                    if idx >= len(batch):
                        break
                    func_context = batch[idx]
                    self.stats["total_analyzed"] += 1
                    if result and result.get("mismatch_detected"):
                        self.stats["mismatches_detected"] += 1
                        mismatches.append((result, func_context))
                        classification_coros.append(
                            self._classify_finding_safe(result, func_context.name)
                        )
                    else:
                        self.stats["no_mismatch"] += 1

                if classification_coros:
                    await asyncio.gather(
                        *classification_coros, return_exceptions=False
                    )
                return mismatches

        self.logger.debug(
            f"Dispatching {len(batches)} batch(es) with "
            f"batch_concurrency={batch_concurrency}, batch_retries={batch_retries}"
        )
        per_batch_results = await asyncio.gather(
            *(_run_batch(i, b) for i, b in enumerate(batches)),
            return_exceptions=False,
        )
        results: List[Tuple[Dict[str, Any], FunctionContext]] = []
        for batch_result in per_batch_results:
            results.extend(batch_result)
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

        Returns:
            Dictionary with analysis statistics including:
            - total_analyzed: Total functions analyzed
            - mismatches_detected: Functions with detected mismatches
            - no_mismatch: Functions with no mismatch
            - skipped_invalid_response: Functions skipped due to invalid LLM response
            - skipped_error: Functions skipped due to errors
        """
        return self.stats.copy()
