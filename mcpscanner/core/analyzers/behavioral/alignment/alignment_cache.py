# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Per-scan alignment result cache keyed by stable evidence (not prompt delimiters)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ....static_analysis.context_extractor import FunctionContext
from .alignment_prompt_builder import AlignmentPromptBuilder

# Bump when cache-key semantics change.
ALIGNMENT_CACHE_VERSION = "1"


@dataclass(frozen=True)
class AlignmentCacheEntry:
    """Validated alignment outcome for one function."""

    result: Dict[str, Any]

    @property
    def mismatch_detected(self) -> bool:
        return bool(self.result.get("mismatch_detected"))


@dataclass
class AlignmentResultCache:
    """In-memory cache scoped to a single behavioral scan."""

    version: str = ALIGNMENT_CACHE_VERSION
    model: str = ""
    _store: Dict[str, AlignmentCacheEntry] = field(default_factory=dict)

    def clear(self) -> None:
        self._store.clear()

    def key_for(
        self,
        func_context: FunctionContext,
        *,
        prompt_builder: AlignmentPromptBuilder,
    ) -> str:
        evidence = prompt_builder.build_analysis_content(func_context)
        digest = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
        return f"{self.version}:{self.model}:{func_context.name}:{digest}"

    def get(self, cache_key: str) -> Optional[AlignmentCacheEntry]:
        return self._store.get(cache_key)

    def put(self, cache_key: str, result: Dict[str, Any]) -> None:
        self._store[cache_key] = AlignmentCacheEntry(
            result=json.loads(json.dumps(result))
        )
