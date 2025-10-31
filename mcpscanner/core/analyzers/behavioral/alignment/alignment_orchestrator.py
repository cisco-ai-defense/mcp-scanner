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
        
        self.logger.info("AlignmentOrchestrator initialized")

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
        try:
            # Step 1: Build alignment verification prompt
            self.logger.debug(f"Building alignment prompt for {func_context.name}")
            try:
                prompt = self.prompt_builder.build_prompt(func_context)
            except Exception as e:
                self.logger.error(f"Prompt building failed for {func_context.name}: {e}", exc_info=True)
                raise
            
            # Step 2: Query LLM for alignment verification
            self.logger.debug(f"Querying LLM for alignment verification of {func_context.name}")
            try:
                response = await self.llm_client.verify_alignment(prompt)
            except Exception as e:
                self.logger.error(f"LLM verification failed for {func_context.name}: {e}", exc_info=True)
                raise
            
            # Step 3: Validate and parse response
            self.logger.debug(f"Validating alignment response for {func_context.name}")
            try:
                result = self.response_validator.validate(response)
            except Exception as e:
                self.logger.error(f"Response validation failed for {func_context.name}: {e}", exc_info=True)
                raise
            
            if not result:
                self.logger.warning(f"Invalid response for {func_context.name}, skipping")
                return None
            
            # Step 4: Return analysis if mismatch detected
            if result.get("mismatch_detected"):
                self.logger.info(f"Alignment mismatch detected in {func_context.name}")
                return (result, func_context)
            else:
                self.logger.debug(f"No alignment mismatch in {func_context.name}")
                return None
            
        except Exception as e:
            self.logger.error(f"Alignment check failed for {func_context.name}: {e}")
            return None
