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

Failure semantics
-----------------
The orchestrator distinguishes three outcomes per function:

* **Mismatch detected** — returns ``(analysis_dict, func_context)``.
* **Verified clean** — returns ``None`` and leaves
  ``errored_function_names`` untouched.
* **Could not verify** — returns ``None`` and adds the function name to
  ``errored_function_names``. Callers must treat that set as inconclusive
  (UNKNOWN), not as a clean result.

``LLM_UNAVAILABLE_KEY`` remains for callers that still receive a sentinel
dict. The current orchestrator records failures on
``errored_function_names`` instead of returning that sentinel.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .....config.config import Config
from .....config.constants import MCPScannerConstants
from .....threats.threats import ThreatMapping
from .....utils.analyzer_errors import (
    ERROR_KIND_TRANSIENT,
    ErrorKind,
    classify_analyzer_error,
    compute_backoff_delay,
)
from .....utils.log_format import sanitize_log_value, truncate
from ....static_analysis.context_extractor import FunctionContext
from .alignment_prompt_builder import AlignmentPromptBuilder
from .alignment_llm_client import AlignmentLLMClient
from .alignment_response_validator import AlignmentResponseValidator, is_unanalysed
from .threat_vulnerability_classifier import ThreatVulnerabilityClassifier


# Legacy marker. The orchestrator does not put this key on results.
# A failed check returns ``None`` and records the function name in
# ``errored_function_names``. ``BehavioralCodeAnalyzer`` turns that set
# into ``severity="UNKNOWN"``. ``_dispatch_finding`` still recognizes
# the key when a caller injects a sentinel dict, and that path emits
# ``severity="ERROR"``.
LLM_UNAVAILABLE_KEY = "_llm_unavailable"


class AlignmentVerificationError(RuntimeError):
    """Unused by the orchestrator. Kept so existing imports keep working.

    ``check_alignment`` does not raise this. An unusable LLM response
    adds the function name to ``errored_function_names`` and returns
    ``None``. Callers emit ``severity="UNKNOWN"`` from that set.
    """


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

    def _record_skipped_error(
        self, exc: BaseException, *, context: str = "llm"
    ) -> ErrorKind:
        """Increment error counters and return the error disposition."""
        kind = classify_analyzer_error(
            exc,
            context=context,
            model=getattr(self.llm_client, "_model", None),
        )
        self.stats["skipped_error"] += 1
        if kind is ErrorKind.TRANSIENT:
            self.stats["skipped_error_transient"] += 1
        else:
            self.stats["skipped_error_final"] += 1
        return kind

    @staticmethod
    def _fresh_stats() -> Dict[str, int]:
        """Return a fresh, zeroed stats dict."""
        return {
            "total_analyzed": 0,
            "mismatches_detected": 0,
            "no_mismatch": 0,
            "skipped_invalid_response": 0,
            "skipped_error": 0,
            "skipped_error_transient": 0,
            "skipped_error_final": 0,
        }

    def reset_stats(self) -> None:
        """Reset cumulative counters to zero."""
        for key in self.stats:
            self.stats[key] = 0
        self.errored_function_names.clear()

    def _alignment_prompt_parts(
        self, func_context: FunctionContext
    ) -> Tuple[Optional[str], str]:
        """Return ``(system_template, user_payload)`` for one function.

        Prefer the system/user split. Fall back to the single-string
        prompt when the builder only implements ``build_prompt``.
        """
        builder = self.prompt_builder
        parts = getattr(builder, "build_prompt_parts", None)
        if parts is not None:
            return parts(func_context)
        return None, builder.build_prompt(func_context)

    def _batch_alignment_prompt_parts(
        self, batch: List[FunctionContext]
    ) -> Tuple[Optional[str], str]:
        """Return ``(system_template, user_payload)`` for a function batch."""
        builder = self.prompt_builder
        parts = getattr(builder, "build_batch_prompt_parts", None)
        if parts is not None:
            return parts(batch)
        body = builder.build_batch_analysis_content(batch)
        return None, builder.wrap_batch_prompt(batch, body)

    async def _verify_alignment(
        self,
        user_payload: str,
        system_template: Optional[str],
        *,
        max_retries: Optional[int] = None,
    ) -> str:
        """Call the LLM client, passing the system role only when set."""
        kwargs: Dict[str, Any] = {}
        if system_template:
            kwargs["system_prompt"] = system_template
        if max_retries is not None:
            kwargs["max_retries"] = max_retries
        return await self.llm_client.verify_alignment(user_payload, **kwargs)

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
            ``(analysis_dict, func_context)`` when a mismatch is detected.
            ``None`` when the function is clean or when verification could
            not complete. Failures also add ``func_context.name`` to
            ``errored_function_names`` so callers can emit UNKNOWN instead
            of SAFE.
        """
        self.stats["total_analyzed"] += 1
        check_start = time.perf_counter()
        stage = "local"

        try:
            # Split the framework template into the system slot so Bedrock
            # Anthropic models return structured JSON instead of ``{}``.
            self.logger.debug(f"Building alignment prompt for {func_context.name}")
            system_template, user_payload = self._alignment_prompt_parts(
                func_context
            )

            stage = "llm"
            self.logger.debug(
                f"Querying LLM for alignment verification of {func_context.name}"
            )
            response = await self._verify_alignment(user_payload, system_template)

            stage = "parse"
            self.logger.debug(f"Validating alignment response for {func_context.name}")
            result = self.response_validator.validate(response)

            if not result:
                # Empty, non-JSON, or incomplete response. Record the
                # function as unverified. Callers read
                # ``errored_function_names`` and emit UNKNOWN. This is
                # not turned into an ERROR sentinel.
                response_excerpt = (
                    (response or "").strip()[:200] if response is not None else ""
                )
                self.logger.warning(
                    f"Invalid response for {func_context.name} "
                    f"(excerpt: {response_excerpt!r})"
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
            kind = self._record_skipped_error(e, context=stage)
            self.logger.error(
                "alignment check failed function=%s duration_ms=%d error_kind=%s "
                "error_type=%s error=%s",
                func_context.name,
                check_ms,
                kind.value,
                type(e).__name__,
                truncate(e),
            )
            name = getattr(func_context, "name", None)
            if name:
                self.errored_function_names.add(name)
            return None

    async def check_alignment_batch(
        self, func_contexts: List[FunctionContext], batch_size: int = 5
    ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
        """Check alignment for multiple functions in batched LLM calls.

        This method batches multiple functions into single LLM requests to
        reduce API calls and improve scanning speed.

        Args:
            func_contexts: List of function contexts to analyze
            batch_size: Number of functions per LLM request (default: 5)

        Returns:
            List of ``(analysis_dict, func_context)`` tuples for functions
            where a mismatch was detected. Verified-clean functions are
            omitted. Functions that could not be verified are also omitted
            here; their names are added to ``errored_function_names``.
            Callers must treat that set as UNKNOWN, not as SAFE and not
            as an ERROR sentinel.

            A result dict that already contains :data:`LLM_UNAVAILABLE_KEY`
            is left for ``BehavioralCodeAnalyzer._dispatch_finding``. This
            method does not create those dicts.
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
            batch = func_contexts[i : i + batch_size]
            batch_idx = i // batch_size + 1
            batch_start = time.perf_counter()
            self.logger.debug(
                "batch %d/%d start size=%d", batch_idx, total_batches, len(batch)
            )

            stage = "local"
            try:
                system_template, user_payload = self._batch_alignment_prompt_parts(
                    batch
                )
                batch_results = None
                parse_attempts = max(
                    1, MCPScannerConstants.LLM_BATCH_PARSE_MAX_ATTEMPTS
                )
                base_delay = MCPScannerConstants.LLM_RETRY_BASE_DELAY

                for parse_attempt in range(parse_attempts):
                    stage = "llm"
                    if parse_attempt == 0:
                        response = await self._verify_alignment(
                            user_payload, system_template
                        )
                    else:
                        # Re-prompt only; first attempt already consumed the
                        # full API retry budget for transient failures.
                        response = await self._verify_alignment(
                            user_payload,
                            system_template,
                            max_retries=1,
                        )
                    stage = "parse"
                    batch_results = self.response_validator.validate_batch(
                        response, len(batch)
                    )
                    if batch_results is not None:
                        break
                    if parse_attempt < parse_attempts - 1:
                        delay = compute_backoff_delay(parse_attempt, base_delay)
                        self.logger.warning(
                            "batch %d/%d invalid_response error_kind=%s "
                            "attempt=%d/%d backoff_s=%.1f fallback=retry_batch",
                            batch_idx,
                            total_batches,
                            ERROR_KIND_TRANSIENT,
                            parse_attempt + 1,
                            parse_attempts,
                            delay,
                        )
                        await asyncio.sleep(delay)

                # ``None`` means hard failure (empty / unparseable response).
                if batch_results is None:
                    self.logger.warning(
                        "batch %d/%d invalid_response fallback=individual size=%d "
                        "-- LLM returned an unparseable batch, retrying "
                        "each function individually",
                        batch_idx,
                        total_batches,
                        len(batch),
                    )
                    for func_context in batch:
                        result = await self.check_alignment(func_context)
                        if result is not None:
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
                    # result for this function. Route to errored —
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
                                    description_claims=result.get(
                                        "description_claims", ""
                                    ),
                                    actual_behavior=result.get("actual_behavior", ""),
                                    security_implications=result.get(
                                        "security_implications", ""
                                    ),
                                    dataflow_evidence=result.get(
                                        "dataflow_evidence", ""
                                    ),
                                )
                                if classification:
                                    result["threat_vulnerability_classification"] = (
                                        classification["classification"]
                                    )
                                else:
                                    result["threat_vulnerability_classification"] = (
                                        "UNCLEAR"
                                    )
                            except Exception as e:
                                self.logger.error(f"Classification failed: {e}")
                                result["threat_vulnerability_classification"] = (
                                    "UNCLEAR"
                                )

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
                kind = classify_analyzer_error(
                    e,
                    context=stage,
                    model=getattr(self.llm_client, "_model", None),
                )
                self.logger.error(
                    "batch %d/%d failed size=%d duration_ms=%d error_kind=%s "
                    "error_type=%s error=%s fallback=individual_analysis",
                    batch_idx,
                    total_batches,
                    len(batch),
                    batch_ms,
                    kind.value,
                    type(e).__name__,
                    truncate(e),
                )
                # NOTE: we do *not* pre-populate ``errored_function_names``
                # for the whole batch. ``check_alignment`` marks errored
                # on raise / invalid-response, and leaves the set
                # untouched on clean / mismatch.
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
            "skipped_invalid_response=%d skipped_error=%d "
            "skipped_error_transient=%d skipped_error_final=%d",
            safe_scope,
            s["total_analyzed"],
            s["mismatches_detected"],
            s["no_mismatch"],
            s["skipped_invalid_response"],
            s["skipped_error"],
            s.get("skipped_error_transient", 0),
            s.get("skipped_error_final", 0),
        )
