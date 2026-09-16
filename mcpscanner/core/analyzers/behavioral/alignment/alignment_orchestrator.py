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
import time
from dataclasses import dataclass
from pathlib import Path
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
from .alignment_cache import AlignmentResultCache
from .threat_vulnerability_classifier import ThreatVulnerabilityClassifier


@dataclass
class _BatchStage:
    """How far a batch got, so a failure can name what it was attempting.

    Carried by reference because the stage advances inside the request
    helper but is only read by the handler that wraps it.
    """

    name: str = "local"


@dataclass
class _BatchTally:
    """Per-batch outcome counts for the completion log."""

    mismatches: int = 0
    clean: int = 0
    unanalysed: int = 0


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
        self._result_cache = AlignmentResultCache(
            model=getattr(self.llm_client, "_model", None) or "unknown"
        )

        self.stats = self._fresh_stats()
        # (source_file, function_name) pairs whose alignment check raised or
        # produced an invalid response in the current scan. Scoped per file so
        # concurrent directory scans cannot cross-contaminate same-named funcs.
        self.errored_function_keys: Set[Tuple[str, str]] = set()

        self.logger.debug("AlignmentOrchestrator initialized")

    @staticmethod
    def _function_key(func_context: Any) -> Tuple[str, str]:
        name = getattr(func_context, "name", None) or ""
        source = getattr(func_context, "source_file", "") or ""
        if source and source != "unknown":
            try:
                source = str(Path(source).resolve(strict=False))
            except (OSError, RuntimeError, ValueError) as exc:
                logging.getLogger(__name__).debug(
                    "alignment function_key path_resolve_failed source=%s error_type=%s error=%s",
                    source,
                    type(exc).__name__,
                    truncate(exc),
                )
        return (source, name)

    def _mark_errored(self, func_context: Any) -> None:
        name = getattr(func_context, "name", None)
        if name:
            self.errored_function_keys.add(self._function_key(func_context))

    def alignment_failed(self, func_context: Any) -> bool:
        """Whether ``func_context``'s alignment check failed in this scan.

        Failures are keyed by the function's *defining* file, which for a
        cross-file handler registration is not the file being scanned, so
        callers must ask through the context rather than rebuild the key
        from the path they happen to be iterating.
        """
        return self._function_key(func_context) in self.errored_function_keys

    @property
    def errored_function_names(self) -> Set[str]:
        """Function names that errored (any source file). Test/diagnostic helper."""
        return {name for _, name in self.errored_function_keys}

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
            "cache_hits": 0,
        }

    def reset_stats(self) -> None:
        """Reset cumulative counters to zero."""
        for key in self.stats:
            self.stats[key] = 0
        self.errored_function_keys.clear()
        self._result_cache.clear()
        self._result_cache.model = getattr(self.llm_client, "_model", None) or "unknown"

    def _cache_lookup(
        self, func_context: FunctionContext
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not MCPScannerConstants.ALIGNMENT_CACHE_ENABLED:
            return None, None
        cache_key = self._result_cache.key_for(
            func_context, prompt_builder=self.prompt_builder
        )
        entry = self._result_cache.get(cache_key)
        if entry is None:
            return None, cache_key
        return entry.result, cache_key

    def _store_cache(self, cache_key: Optional[str], result: Dict[str, Any]) -> None:
        if cache_key and MCPScannerConstants.ALIGNMENT_CACHE_ENABLED:
            self._result_cache.put(cache_key, result)

    def _return_cached_result(
        self,
        func_context: FunctionContext,
        result: Dict[str, Any],
    ) -> Optional[Tuple[Dict[str, Any], FunctionContext]]:
        self.stats["total_analyzed"] += 1
        self.stats["cache_hits"] += 1
        if result.get("mismatch_detected"):
            self.stats["mismatches_detected"] += 1
            return (result, func_context)
        self.stats["no_mismatch"] += 1
        return None

    async def check_alignment(
        self, func_context: FunctionContext
    ) -> Optional[Tuple[Dict[str, Any], FunctionContext]]:
        """Check whether a function's behavior matches what it claims to do.

        The single-function path: build the evidence prompt, ask the LLM,
        validate the reply, and classify a mismatch. Returns the analysis
        paired with its context when the function misrepresents itself, and
        None when it is aligned or could not be analyzed.
        """
        check_start = time.perf_counter()
        stage = _BatchStage()

        cached_result, cache_key = self._cache_lookup(func_context)
        if cached_result is not None:
            self.logger.debug("alignment cache_hit function=%s", func_context.name)
            return self._return_cached_result(func_context, cached_result)

        self.stats["total_analyzed"] += 1

        try:
            prompt = self.prompt_builder.build_prompt(func_context)

            stage.name = "llm"
            response = await self.llm_client.verify_alignment(prompt)

            stage.name = "parse"
            result = self.response_validator.validate(response)
            if not result:
                self.logger.warning(
                    "alignment invalid_response function=%s source_file=%s stage=parse",
                    func_context.name,
                    sanitize_log_value(getattr(func_context, "source_file", "")),
                )
                self.stats["skipped_invalid_response"] += 1
                self._mark_errored(func_context)
                return None

            check_ms = int((time.perf_counter() - check_start) * 1000)

            if not result.get("mismatch_detected"):
                self.logger.debug(
                    "alignment ok function=%s duration_ms=%d",
                    func_context.name,
                    check_ms,
                )
                self.stats["no_mismatch"] += 1
                self._store_cache(cache_key, result)
                return None

            self.logger.info(
                "alignment mismatch function=%s threat=%s duration_ms=%d",
                func_context.name,
                result.get("threat_name", "<unset>") or "<unset>",
                check_ms,
            )
            self.stats["mismatches_detected"] += 1
            await self._classify_mismatch(result, func_context)
            self._store_cache(cache_key, result)
            return (result, func_context)

        except Exception as e:
            kind = self._record_skipped_error(e, context=stage.name)
            self.logger.error(
                "alignment check failed function=%s source_file=%s stage=%s duration_ms=%d "
                "error_kind=%s error_type=%s error=%s",
                func_context.name,
                sanitize_log_value(getattr(func_context, "source_file", "")),
                stage.name,
                int((time.perf_counter() - check_start) * 1000),
                kind.value,
                type(e).__name__,
                truncate(e),
                exc_info=True,
            )
            self._mark_errored(func_context)
            return None

    async def check_alignment_batch(
        self,
        func_contexts: List[FunctionContext],
        batch_size: int = 5,
        *,
        max_concurrency: int | None = None,
    ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
        """Check alignment for multiple functions in batched LLM calls.

        Batches are submitted concurrently up to ``max_concurrency`` to
        reduce wall-clock time on multi-function scans.

        Args:
            func_contexts: List of function contexts to analyze
            batch_size: Number of functions per LLM request (default: 5)
            max_concurrency: Parallel batch limit (default: from constants)

        Returns:
            List of (analysis_dict, func_context) tuples for detected mismatches
        """
        if not func_contexts:
            return []

        concurrency = max(
            1,
            max_concurrency or MCPScannerConstants.BEHAVIORAL_LLM_BATCH_CONCURRENCY,
        )
        batches = [
            func_contexts[i : i + batch_size]
            for i in range(0, len(func_contexts), batch_size)
        ]
        total_funcs = len(func_contexts)
        total_batches = len(batches)
        self.logger.info(
            "alignment batch scan start total_functions=%d batches=%d "
            "batch_size=%d concurrency=%d",
            total_funcs,
            total_batches,
            batch_size,
            concurrency,
        )

        semaphore = asyncio.Semaphore(concurrency)

        async def _run_batch(
            batch_idx: int, batch: List[FunctionContext]
        ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
            async with semaphore:
                return await self._process_alignment_batch(
                    batch,
                    batch_idx=batch_idx,
                    total_batches=total_batches,
                )

        batch_outputs = await asyncio.gather(
            *(_run_batch(idx + 1, batch) for idx, batch in enumerate(batches))
        )
        results: List[Tuple[Dict[str, Any], FunctionContext]] = []
        for batch_result in batch_outputs:
            results.extend(batch_result)
        return results

    async def _process_alignment_batch(
        self,
        batch: List[FunctionContext],
        *,
        batch_idx: int,
        total_batches: int,
    ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
        """Process one alignment batch (single LLM request + parse/classify).

        Batch failures degrade rather than drop: an unparseable reply or a
        raised exception re-asks one function at a time, which costs more
        requests but keeps the batch's findings.
        """
        results, pending = self._partition_cached(batch)
        if not pending:
            return results

        pending_contexts = [ctx for ctx, _ in pending]
        batch_start = time.perf_counter()
        self.logger.debug(
            "batch %d/%d start size=%d cached=%d",
            batch_idx,
            total_batches,
            len(pending_contexts),
            len(batch) - len(pending_contexts),
        )

        stage = _BatchStage()
        try:
            batch_results = await self._request_batch_verdicts(
                pending_contexts,
                stage,
                batch_idx=batch_idx,
                total_batches=total_batches,
            )

            if batch_results is None:
                self.logger.warning(
                    "batch %d/%d invalid_response fallback=individual size=%d "
                    "-- LLM returned an unparseable batch, retrying each function individually",
                    batch_idx,
                    total_batches,
                    len(pending_contexts),
                )
                results.extend(await self._analyze_individually(pending))
                return results

            tally = await self._record_batch_verdicts(batch_results, pending, results)
            self.logger.info(
                "batch %d/%d done size=%d mismatches=%d clean=%d "
                "unanalysed=%d duration_ms=%d",
                batch_idx,
                total_batches,
                len(pending_contexts),
                tally.mismatches,
                tally.clean,
                tally.unanalysed,
                int((time.perf_counter() - batch_start) * 1000),
            )
            return results

        except Exception as e:
            kind = classify_analyzer_error(
                e,
                context=stage.name,
                model=getattr(self.llm_client, "_model", None),
            )
            self.logger.error(
                "batch %d/%d failed size=%d duration_ms=%d stage=%s error_kind=%s "
                "error_type=%s error=%s fallback=individual_analysis",
                batch_idx,
                total_batches,
                len(pending_contexts),
                int((time.perf_counter() - batch_start) * 1000),
                stage.name,
                kind.value,
                type(e).__name__,
                truncate(e),
                exc_info=True,
            )
            results.extend(await self._analyze_individually(pending))
            return results

    def _partition_cached(self, batch: List[FunctionContext]) -> Tuple[
        List[Tuple[Dict[str, Any], FunctionContext]],
        List[Tuple[FunctionContext, Optional[str]]],
    ]:
        """Split a batch into results already known and functions still to ask."""
        results: List[Tuple[Dict[str, Any], FunctionContext]] = []
        pending: List[Tuple[FunctionContext, Optional[str]]] = []
        for func_context in batch:
            cached_result, cache_key = self._cache_lookup(func_context)
            if cached_result is not None:
                hit = self._return_cached_result(func_context, cached_result)
                if hit:
                    results.append(hit)
                continue
            pending.append((func_context, cache_key))
        return results, pending

    async def _request_batch_verdicts(
        self,
        pending_contexts: List[FunctionContext],
        stage: "_BatchStage",
        *,
        batch_idx: int,
        total_batches: int,
    ) -> Optional[List[Any]]:
        """Ask for one verdict per function, re-prompting unparseable replies.

        Returns None once the attempts are spent, which is the caller's cue
        to fall back to individual checks.
        """
        batch_body = self.prompt_builder.build_batch_analysis_content(pending_contexts)
        attempts = max(1, MCPScannerConstants.LLM_BATCH_PARSE_MAX_ATTEMPTS)
        base_delay = MCPScannerConstants.LLM_RETRY_BASE_DELAY

        for attempt in range(attempts):
            prompt = self.prompt_builder.wrap_batch_prompt(pending_contexts, batch_body)
            stage.name = "llm"
            # A reply we could not parse is not a transport fault, so the
            # client should not layer its own retries beneath this loop.
            if attempt == 0:
                response = await self.llm_client.verify_alignment(prompt)
            else:
                response = await self.llm_client.verify_alignment(prompt, max_retries=1)

            stage.name = "parse"
            batch_results = self.response_validator.validate_batch(
                response, len(pending_contexts)
            )
            if batch_results is not None:
                return batch_results

            if attempt < attempts - 1:
                delay = compute_backoff_delay(attempt, base_delay)
                self.logger.warning(
                    "batch %d/%d invalid_response error_kind=%s "
                    "attempt=%d/%d backoff_s=%.1f fallback=retry_batch",
                    batch_idx,
                    total_batches,
                    ERROR_KIND_TRANSIENT,
                    attempt + 1,
                    attempts,
                    delay,
                )
                await asyncio.sleep(delay)

        return None

    async def _record_batch_verdicts(
        self,
        batch_results: List[Any],
        pending: List[Tuple[FunctionContext, Optional[str]]],
        results: List[Tuple[Dict[str, Any], FunctionContext]],
    ) -> "_BatchTally":
        """Fold each verdict into the stats, the cache, and ``results``.

        A model that returns more verdicts than the batch held is truncated
        rather than trusted, since the surplus cannot be attributed to a
        function.
        """
        tally = _BatchTally()
        for idx, result in enumerate(batch_results):
            if idx >= len(pending):
                break

            func_context, cache_key = pending[idx]
            self.stats["total_analyzed"] += 1

            if is_unanalysed(result):
                self.stats["skipped_invalid_response"] += 1
                tally.unanalysed += 1
                self._mark_errored(func_context)
                continue

            if result and result.get("mismatch_detected"):
                self.stats["mismatches_detected"] += 1
                tally.mismatches += 1
                await self._classify_mismatch(result, func_context)
                self._store_cache(cache_key, result)
                results.append((result, func_context))
            else:
                self.stats["no_mismatch"] += 1
                tally.clean += 1
                self._store_cache(cache_key, result)

        return tally

    async def _classify_mismatch(
        self, result: Dict[str, Any], func_context: FunctionContext
    ) -> None:
        """Label a mismatch threat-vs-vulnerability, in place.

        A classifier that raises or returns nothing leaves the finding
        UNCLEAR. Losing the label is tolerable; losing the finding is not.
        """
        threat_name = result.get("threat_name", "")
        if threat_name == "GENERAL DESCRIPTION-CODE MISMATCH":
            return

        try:
            classification = await self.threat_vuln_classifier.classify_finding(
                threat_name=threat_name or "UNKNOWN",
                severity=self._get_mapped_severity(threat_name),
                summary=result.get("summary", ""),
                description_claims=result.get("description_claims", ""),
                actual_behavior=result.get("actual_behavior", ""),
                security_implications=result.get("security_implications", ""),
                dataflow_evidence=result.get("dataflow_evidence", ""),
            )
        except Exception as e:
            self.logger.error(
                "alignment classify_failed function=%s threat=%s "
                "error_type=%s error=%s",
                func_context.name,
                threat_name or "<unset>",
                type(e).__name__,
                truncate(e),
                exc_info=True,
            )
            result["threat_vulnerability_classification"] = "UNCLEAR"
            return

        if not classification:
            self.logger.warning(
                "alignment classify_empty function=%s threat=%s",
                func_context.name,
                threat_name or "<unset>",
            )
            result["threat_vulnerability_classification"] = "UNCLEAR"
            return

        result["threat_vulnerability_classification"] = classification["classification"]

    async def _analyze_individually(
        self, pending: List[Tuple[FunctionContext, Optional[str]]]
    ) -> List[Tuple[Dict[str, Any], FunctionContext]]:
        """Re-ask function by function after the batch as a whole failed."""
        recovered: List[Tuple[Dict[str, Any], FunctionContext]] = []
        for func_context, _ in pending:
            result = await self.check_alignment(func_context)
            if result:
                recovered.append(result)
        return recovered

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
            "cache_hits=%d skipped_invalid_response=%d skipped_error=%d "
            "skipped_error_transient=%d skipped_error_final=%d",
            safe_scope,
            s["total_analyzed"],
            s["mismatches_detected"],
            s["no_mismatch"],
            s.get("cache_hits", 0),
            s["skipped_invalid_response"],
            s["skipped_error"],
            s.get("skipped_error_transient", 0),
            s.get("skipped_error_final", 0),
        )
