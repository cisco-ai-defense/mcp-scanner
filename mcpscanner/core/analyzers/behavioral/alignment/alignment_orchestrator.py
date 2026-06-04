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
from typing import Any, Dict, List, Optional, Tuple

from .....config.config import Config
from .....config.constants import MCPScannerConstants
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

        # Bounded LLM concurrency. Prefer a per-orchestrator semaphore
        # over a module-global one so unit tests that instantiate
        # multiple orchestrators don't share state, while still letting
        # each ``analyze()`` invocation cap parallel in-flight requests
        # at ``MCP_SCANNER_LLM_CONCURRENCY``. Created lazily inside an
        # event loop in ``_get_llm_semaphore`` because constructing
        # ``asyncio.Semaphore`` outside a running loop is brittle.
        self._llm_concurrency = MCPScannerConstants.LLM_CONCURRENCY
        self._llm_semaphore: Optional[asyncio.Semaphore] = None

        self.logger.debug(
            "AlignmentOrchestrator initialized "
            f"(llm_concurrency={self._llm_concurrency})"
        )

    def _get_llm_semaphore(self) -> asyncio.Semaphore:
        """Return the per-orchestrator LLM concurrency limiter.

        Lazily creates the semaphore on first use so it binds to the
        currently running event loop. Without this, repeated calls
        from different loops (e.g. unit tests using ``asyncio.run``
        on the same orchestrator) would silently share a semaphore
        bound to a closed loop.
        """
        if self._llm_semaphore is None:
            self._llm_semaphore = asyncio.Semaphore(self._llm_concurrency)
        return self._llm_semaphore

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
            # Step 1: Build alignment verification prompt. Split the
            # static template from the per-call evidence so prompt
            # caching can engage on Anthropic-family models.
            self.logger.debug(f"Building alignment prompt for {func_context.name}")
            try:
                evidence = self.prompt_builder.build_evidence(func_context)
                cacheable_template = self.prompt_builder.template_text
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
                response = await self.llm_client.verify_alignment(
                    "",
                    cacheable_template=cacheable_template,
                    evidence=evidence,
                )
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
                self.logger.debug(f"No alignment mismatch in {func_context.name}")
                self.stats["no_mismatch"] += 1
                return None

        except Exception as e:
            self.logger.error(f"Alignment check failed for {func_context.name}: {e}")
            self.stats["skipped_error"] += 1
            return None

    async def check_alignment_batch(
        self, func_contexts: List[FunctionContext], batch_size: int = 5
    ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
        """Check alignment for multiple functions in batched LLM calls.

        Batches are dispatched concurrently and capped by the
        per-orchestrator LLM semaphore (``MCP_SCANNER_LLM_CONCURRENCY``),
        so a 120-tool scan completes in ``ceil(num_batches /
        concurrency)`` round trips instead of ``num_batches`` round
        trips. The previous implementation awaited each batch
        sequentially inside a ``for`` loop, which dominated the wall
        clock on every scan.

        Threat-vulnerability classification (a separate LLM call per
        flagged mismatch) is also dispatched in parallel under the
        same semaphore for the same reason.

        Args:
            func_contexts: List of function contexts to analyze.
            batch_size: Number of functions per LLM request
                (default: 5). Larger batches reduce request count but
                each request carries more risk of partial-failure
                fallback to per-function analysis.

        Returns:
            List of ``(analysis_dict, func_context)`` tuples for
            detected mismatches. Order matches input order so callers
            that zip results with ``func_contexts`` still work.
        """
        if not func_contexts:
            return []

        # Slice into batches once. Keep the original index of every
        # function so we can preserve input order in the output.
        batches: List[List[FunctionContext]] = [
            func_contexts[i:i + batch_size]
            for i in range(0, len(func_contexts), batch_size)
        ]
        self.logger.debug(
            f"Dispatching {len(batches)} batch(es) of up to {batch_size} "
            f"function(s) with concurrency={self._llm_concurrency}"
        )

        # Phase 1: run all batches concurrently. Each task returns a
        # list of ``(global_index, result_or_none, func_context)``
        # entries. ``return_exceptions=True`` so one bad batch can't
        # tear down the whole gather.
        offsets = [i * batch_size for i in range(len(batches))]
        gathered = await asyncio.gather(
            *(
                self._run_one_batch(batch, offset)
                for batch, offset in zip(batches, offsets)
            ),
            return_exceptions=True,
        )

        # Phase 2: collect the raw alignment results, in order, and
        # decide which need a follow-up classifier call.
        #
        # ``raw[i]`` corresponds to ``func_contexts[i]`` after Phase 1.
        # ``None`` means "no mismatch" or "task failed and was already
        # accounted for in stats". Phase 3 only acts on truthy entries.
        raw: List[Optional[Tuple[Dict[str, Any], FunctionContext]]] = (
            [None] * len(func_contexts)
        )
        classify_indices: List[int] = []
        for batch_outcome in gathered:
            if isinstance(batch_outcome, BaseException):
                # ``_run_one_batch`` already converted internal failures
                # into per-function ``None`` entries; reaching this branch
                # means an unexpected exception escaped (e.g. asyncio
                # cancellation). Log and continue — we'd rather lose one
                # batch's findings than abort the whole scan.
                self.logger.error(
                    f"Batch task raised unexpectedly: {batch_outcome}"
                )
                continue
            for global_idx, item in batch_outcome:
                if item is None:
                    continue
                raw[global_idx] = item
                result_dict, _ = item
                threat_name = (result_dict or {}).get("threat_name", "")
                # Classifier is skipped for the catch-all label and
                # for entries that already carry a classification (e.g.
                # populated by ``check_alignment`` fallback path).
                if (
                    threat_name
                    and threat_name != "GENERAL DESCRIPTION-CODE MISMATCH"
                    and "threat_vulnerability_classification" not in result_dict
                ):
                    classify_indices.append(global_idx)

        # Phase 3: classifier fan-out under the same LLM semaphore.
        if classify_indices:
            self.logger.debug(
                f"Classifying {len(classify_indices)} flagged finding(s) "
                "in parallel"
            )
            classifications = await asyncio.gather(
                *(
                    self._classify_with_semaphore(raw[idx][0])
                    for idx in classify_indices
                ),
                return_exceptions=True,
            )
            for idx, classification in zip(classify_indices, classifications):
                result_dict, _ = raw[idx]
                if isinstance(classification, BaseException):
                    self.logger.error(
                        f"Classification failed: {classification}"
                    )
                    result_dict["threat_vulnerability_classification"] = (
                        "UNCLEAR"
                    )
                elif classification:
                    result_dict["threat_vulnerability_classification"] = (
                        classification["classification"]
                    )
                else:
                    result_dict["threat_vulnerability_classification"] = (
                        "UNCLEAR"
                    )

        return [item for item in raw if item is not None]

    async def _run_one_batch(
        self,
        batch: List[FunctionContext],
        offset: int,
    ) -> List["Tuple[int, Optional[Tuple[Dict[str, Any], FunctionContext]]]"]:
        """Run a single batched LLM call and translate it into per-function
        outcomes tagged with their global indices.

        Falls back to per-function ``check_alignment`` when:
        - the batch prompt build / LLM call raises, or
        - the response validator can't parse a per-function array.

        Returns one entry per function in the batch (in input order).
        """
        outcomes: List[
            "Tuple[int, Optional[Tuple[Dict[str, Any], FunctionContext]]]"
        ] = []

        try:
            evidence = self.prompt_builder.build_batch_evidence(batch)
            cacheable_template = self.prompt_builder.template_text
            async with self._get_llm_semaphore():
                response = await self.llm_client.verify_alignment(
                    "",
                    cacheable_template=cacheable_template,
                    evidence=evidence,
                )
            batch_results = self.response_validator.validate_batch(
                response, len(batch)
            )
        except Exception as e:
            # Whole-batch failure: degrade gracefully to per-function
            # analysis, still under the global LLM semaphore.
            self.logger.warning(
                f"Batch analysis failed ({e!r}); falling back to per-function"
            )
            return await self._fallback_individual(batch, offset)

        if not batch_results:
            self.logger.warning(
                "Invalid batch response, falling back to per-function analysis"
            )
            return await self._fallback_individual(batch, offset)

        for idx, func_context in enumerate(batch):
            global_idx = offset + idx
            self.stats["total_analyzed"] += 1
            result = batch_results[idx] if idx < len(batch_results) else None

            if not result:
                self.stats["no_mismatch"] += 1
                outcomes.append((global_idx, None))
                continue

            if result.get("mismatch_detected"):
                self.stats["mismatches_detected"] += 1
                outcomes.append((global_idx, (result, func_context)))
            else:
                self.stats["no_mismatch"] += 1
                outcomes.append((global_idx, None))

        return outcomes

    async def _fallback_individual(
        self,
        batch: List[FunctionContext],
        offset: int,
    ) -> List[
        "Tuple[int, Optional[Tuple[Dict[str, Any], FunctionContext]]]"
    ]:
        """Per-function fallback when a batch fails.

        Runs the per-function checks concurrently — the LLM semaphore
        already throttles the total in-flight count, so we don't
        de-parallelize the rest of the scan just because one batch
        choked.
        """
        async def _one(func_context: FunctionContext, idx: int):
            try:
                async with self._get_llm_semaphore():
                    res = await self.check_alignment(func_context)
            except Exception as e:
                self.logger.error(
                    f"Per-function fallback failed for "
                    f"{getattr(func_context, 'name', '?')}: {e}"
                )
                res = None
            return (offset + idx, res)

        return await asyncio.gather(
            *(_one(fc, i) for i, fc in enumerate(batch))
        )

    async def _classify_with_semaphore(
        self, result: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Run threat-vulnerability classification under the LLM semaphore."""
        threat_name = result.get("threat_name", "") or "UNKNOWN"
        mapped_severity = self._get_mapped_severity(threat_name)
        async with self._get_llm_semaphore():
            return await self.threat_vuln_classifier.classify_finding(
                threat_name=threat_name,
                severity=mapped_severity,
                summary=result.get("summary", ""),
                description_claims=result.get("description_claims", ""),
                actual_behavior=result.get("actual_behavior", ""),
                security_implications=result.get("security_implications", ""),
                dataflow_evidence=result.get("dataflow_evidence", ""),
            )

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
