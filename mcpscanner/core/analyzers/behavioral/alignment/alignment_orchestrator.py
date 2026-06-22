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
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .....config.config import Config
from .....threats.threats import ThreatMapping
from ....static_analysis.context_extractor import FunctionContext
from .alignment_prompt_builder import AlignmentPromptBuilder
from .alignment_llm_client import AlignmentLLMClient
from .alignment_response_validator import AlignmentResponseValidator
from .threat_vulnerability_classifier import ThreatVulnerabilityClassifier


# Characters that would break naive ``key=value`` log parsers when present
# inside a structured value (whitespace ends a field; ``=`` introduces a
# new pseudo-field; quotes confuse aggregators that try to unwrap them).
_LOG_VALUE_SCRUB = re.compile(r"[\s=\"'`]")

# Cap on the size of any exception message interpolated into a log line.
# ``litellm`` exceptions occasionally include base64-encoded request body
# echoes (especially Bedrock validation failures); truncating keeps log
# aggregator events bounded without losing the root cause.
_ERROR_TRUNCATE = 400


def _truncate_error(value: object) -> str:
    """Return ``str(value)`` clipped to :data:`_ERROR_TRUNCATE` chars.

    The trailing ``…(+N)`` marker indicates how many characters were
    dropped so operators know to look at upstream tracebacks if the
    message is interesting.
    """
    s = str(value)
    if len(s) <= _ERROR_TRUNCATE:
        return s
    return f"{s[:_ERROR_TRUNCATE]}…(+{len(s) - _ERROR_TRUNCATE})"


def _sanitise_log_value(value: str) -> str:
    """Replace whitespace, ``=`` and quote characters with ``_``.

    Operators see e.g. ``scope=directory:/My_Project/server.py`` instead of
    ``scope=directory:/My Project/server.py`` (which breaks key=value
    extractors in Splunk / CloudWatch Insights / Datadog) or
    ``scope=foo bar=hax`` (which is field-injection-shaped).
    """
    if not value:
        return "-"
    return _LOG_VALUE_SCRUB.sub("_", str(value))


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

        # Track analysis statistics. These are cumulative across the orchestrator's
        # lifetime; callers should snapshot via :meth:`stats_snapshot` and compute
        # a delta if they want per-scan numbers, or call :meth:`reset_stats` at
        # the start of a logical scan to zero them.
        self.stats = self._fresh_stats()

        self.logger.debug("AlignmentOrchestrator initialized")

    @staticmethod
    def _fresh_stats() -> Dict[str, int]:
        """Return a fresh, zeroed stats dict.

        Centralised so ``__init__`` and ``reset_stats`` can't drift on keys.
        """
        return {
            "total_analyzed": 0,
            "mismatches_detected": 0,
            "no_mismatch": 0,
            "skipped_invalid_response": 0,
            "skipped_error": 0,
        }

    def reset_stats(self) -> None:
        """Reset cumulative counters to zero.

        Call this at the start of a logical scan when you want the next
        ``log_summary()`` / ``check_alignment_batch`` "done" line to
        describe just that scan instead of the orchestrator's lifetime.
        ``BehavioralCodeAnalyzer.analyze`` calls this once per invocation.
        """
        for key in self.stats:
            self.stats[key] = 0

    def stats_snapshot(self) -> Dict[str, int]:
        """Return a shallow copy of current stats — useful for delta math."""
        return dict(self.stats)

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
                # Truncate so a multi-KB litellm error body can't bloat
                # the operator-facing log line.
                _truncate_error(e),
            )
            self.stats["skipped_error"] += 1
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
        # Snapshot cumulative stats so the "done" line below reports the delta
        # produced by THIS call only. ``self.stats`` is otherwise lifetime-
        # cumulative across all batches the orchestrator has ever processed —
        # logging that as the per-scan total was misleading in long-lived
        # processes (API server, daemonised CLI).
        stats_before = self.stats_snapshot()
        # One-shot INFO so operators see the planned shape of the scan
        # before potentially-long LLM calls start consuming wall time.
        self.logger.info(
            "alignment batch scan start total_functions=%d batches=%d batch_size=%d",
            total_funcs,
            total_batches,
            batch_size,
        )
        scan_start = time.perf_counter()

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

                if not batch_results:
                    self.logger.warning(
                        "batch %d/%d invalid_response fallback=individual size=%d "
                        "-- LLM returned an unparseable batch, retrying each function individually",
                        batch_idx,
                        total_batches,
                        len(batch),
                    )
                    # Fallback to individual analysis
                    for func_context in batch:
                        result = await self.check_alignment(func_context)
                        if result:
                            results.append(result)
                    continue
                
                # Process each result in the batch
                batch_mismatches = 0
                batch_clean = 0
                for idx, result in enumerate(batch_results):
                    if idx >= len(batch):
                        break

                    func_context = batch[idx]
                    self.stats["total_analyzed"] += 1

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
                    "batch %d/%d done size=%d mismatches=%d clean=%d duration_ms=%d",
                    batch_idx,
                    total_batches,
                    len(batch),
                    batch_mismatches,
                    batch_clean,
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
                    _truncate_error(e),
                )
                # Fallback to individual analysis. ``check_alignment``
                # already catches and logs its own exceptions and
                # returns ``None`` on failure (incrementing
                # ``stats["skipped_error"]``), so we don't need an inner
                # try/except here — wrapping it again would swallow a
                # future regression where the function does start
                # re-raising and hide the real cause.
                for func_context in batch:
                    result = await self.check_alignment(func_context)
                    if result:
                        results.append(result)

        scan_ms = int((time.perf_counter() - scan_start) * 1000)
        # Report the delta vs ``stats_before`` so this line describes only
        # this batch scan, not the orchestrator's cumulative lifetime.
        self.logger.info(
            "alignment batch scan done total_functions=%d analyzed=%d mismatches=%d "
            "clean=%d skipped_error=%d skipped_invalid_response=%d duration_ms=%d",
            total_funcs,
            self.stats["total_analyzed"] - stats_before["total_analyzed"],
            self.stats["mismatches_detected"] - stats_before["mismatches_detected"],
            self.stats["no_mismatch"] - stats_before["no_mismatch"],
            self.stats["skipped_error"] - stats_before["skipped_error"],
            self.stats["skipped_invalid_response"]
            - stats_before["skipped_invalid_response"],
            scan_ms,
        )
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

    def log_summary(
        self,
        scope: str = "behavioral",
        *,
        baseline: Optional[Dict[str, int]] = None,
    ) -> None:
        """Emit a single grep-friendly INFO summary line for the current stats.

        Intended to be called at the end of a behavioral scan
        (``BehavioralCodeAnalyzer.analyze``) so operators get one stable
        line per scan that captures the LLM verification outcome:

        ``alignment summary scope=<scope> total=… mismatches=… clean=…
        skipped_invalid_response=… skipped_error=…``

        Designed for log aggregators (CloudWatch Insights, Datadog,
        Splunk) — the key=value shape parses cleanly without a custom
        formatter. Callers don't have to log this themselves; calling
        ``log_summary()`` keeps the line text stable across versions.

        Args:
            scope: Free-form label to disambiguate when the same scanner
                runs the orchestrator more than once in a process. The
                value is sanitised by the caller (spaces/``=`` replaced)
                before being interpolated into the line.
            baseline: Optional snapshot of ``self.stats`` captured at the
                start of the logical scan. When supplied, the line
                reports the delta relative to that snapshot instead of
                the orchestrator's lifetime counters. The orchestrator
                is reused across scans in long-lived processes (API
                server, daemonised CLI); without a baseline the numbers
                would silently grow forever.
        """
        s = self.stats
        b = baseline or {key: 0 for key in s}
        # Sanitise scope so a hostile tool name like "foo bar=hax" can't
        # masquerade as a structured field. Mirrors the same sanitisation
        # logic in BehavioralCodeAnalyzer so callers pre-sanitising stays
        # safe.
        safe_scope = _sanitise_log_value(scope)
        self.logger.info(
            "alignment summary scope=%s total=%d mismatches=%d clean=%d "
            "skipped_invalid_response=%d skipped_error=%d",
            safe_scope,
            s["total_analyzed"] - b.get("total_analyzed", 0),
            s["mismatches_detected"] - b.get("mismatches_detected", 0),
            s["no_mismatch"] - b.get("no_mismatch", 0),
            s["skipped_invalid_response"] - b.get("skipped_invalid_response", 0),
            s["skipped_error"] - b.get("skipped_error", 0),
        )
