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
from typing import Any, Dict, Optional, Tuple

from .....config.config import Config
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
            "skipped_error": 0
        }
        
        self.logger.debug("AlignmentOrchestrator initialized")

    async def check_alignment(
        self,
        func_context: FunctionContext
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
                self.logger.error(f"Prompt building failed for {func_context.name}: {e}", exc_info=True)
                self.stats["skipped_error"] += 1
                raise
            
            # Step 2: Query LLM for alignment verification
            self.logger.debug(f"Querying LLM for alignment verification of {func_context.name}")
            try:
                response = await self.llm_client.verify_alignment(prompt)
            except Exception as e:
                self.logger.error(f"LLM verification failed for {func_context.name}: {e}", exc_info=True)
                self.stats["skipped_error"] += 1
                raise
            
            # Step 3: Validate and parse response
            self.logger.debug(f"Validating alignment response for {func_context.name}")
            try:
                result = self.response_validator.validate(response)
            except Exception as e:
                self.logger.error(f"Response validation failed for {func_context.name}: {e}", exc_info=True)
                self.stats["skipped_error"] += 1
                raise
            
            if not result:
                self.logger.warning(f"Invalid response for {func_context.name}, skipping")
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
                    self.logger.debug(f"Classifying finding as threat or vulnerability for {func_context.name}")
                    try:
                        classification = await self.threat_vuln_classifier.classify_finding(
                            threat_name=result.get("threat_name", "UNKNOWN"),
                            severity=result.get("severity", "UNKNOWN"),
                            summary=result.get("summary", ""),
                            description_claims=result.get("description_claims", ""),
                            actual_behavior=result.get("actual_behavior", ""),
                            security_implications=result.get("security_implications", ""),
                            dataflow_evidence=result.get("dataflow_evidence", "")
                        )
                        if classification:
                            # Add just the classification value to the result
                            result["threat_vulnerability_classification"] = classification['classification']
                            self.logger.debug(f"Classified as {classification['classification']} with {classification['confidence']} confidence")
                        else:
                            self.logger.warning(f"Failed to classify finding for {func_context.name}")
                            result["threat_vulnerability_classification"] = "UNCLEAR"
                    except Exception as e:
                        self.logger.error(f"Classification failed for {func_context.name}: {e}", exc_info=True)
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
