# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""In-memory and optional disk cache for per-file graph extraction."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic, TypeVar

from .models import CodeGraph

T = TypeVar("T")

# Bump when graph extraction semantics change.
GRAPH_EXTRACTOR_VERSION = "18"


@dataclass
class GraphCache(Generic[T]):
    """Content-addressed cache keyed by file hash and extractor version."""

    version: str = GRAPH_EXTRACTOR_VERSION
    _store: dict[str, T] = field(default_factory=dict)

    @staticmethod
    def file_hash(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def key(self, path: str, content: str) -> str:
        return f"{self.version}:{path}:{self.file_hash(content)}"

    def get(self, path: str, content: str) -> T | None:
        return self._store.get(self.key(path, content))

    def put(self, path: str, content: str, value: T) -> None:
        self._store[self.key(path, content)] = value

    def clear(self) -> None:
        self._store.clear()


@dataclass
class CodeGraphCache:
    """Memory cache with optional on-disk persistence for ``CodeGraph`` partials."""

    version: str = GRAPH_EXTRACTOR_VERSION
    cache_dir: Path | None = None
    _memory: GraphCache[CodeGraph] = field(init=False)

    def __post_init__(self) -> None:
        self._memory = GraphCache[CodeGraph](version=self.version)
        if self.cache_dir is not None:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def key(self, path: str, content: str) -> str:
        return self._memory.key(path, content)

    def get(self, path: str, content: str) -> CodeGraph | None:
        hit = self._memory.get(path, content)
        if hit is not None:
            return hit
        if self.cache_dir is None:
            return None
        disk_path = self._disk_path(path, content)
        if not disk_path.is_file():
            return None
        try:
            payload = json.loads(disk_path.read_text(encoding="utf-8"))
            graph = CodeGraph.from_dict(payload)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None
        self._memory.put(path, content, graph)
        return graph

    def put(self, path: str, content: str, value: CodeGraph) -> None:
        self._memory.put(path, content, value)
        if self.cache_dir is None:
            return
        disk_path = self._disk_path(path, content)
        try:
            self._atomic_write_json(disk_path, value.to_dict())
        except OSError:
            return

    def clear(self) -> None:
        self._memory.clear()

    def merged_key(self, language: str, files: dict[str, str]) -> str:
        parts = sorted(f"{path}:{GraphCache.file_hash(source)}" for path, source in files.items())
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
        return f"{self.version}:merged:{language}:{digest}"

    def get_merged(self, language: str, files: dict[str, str]) -> CodeGraph | None:
        key = self.merged_key(language, files)
        hit = self._memory._store.get(key)
        if hit is not None:
            return hit
        if self.cache_dir is None:
            return None
        disk_path = self._merged_disk_path(key)
        if not disk_path.is_file():
            return None
        try:
            payload = json.loads(disk_path.read_text(encoding="utf-8"))
            graph = CodeGraph.from_dict(payload)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None
        self._memory._store[key] = graph
        return graph

    def put_merged(self, language: str, files: dict[str, str], value: CodeGraph) -> None:
        key = self.merged_key(language, files)
        self._memory._store[key] = value
        if self.cache_dir is None:
            return
        disk_path = self._merged_disk_path(key)
        try:
            self._atomic_write_json(disk_path, value.to_dict())
        except OSError:
            return

    def _atomic_write_json(self, disk_path: Path, payload: dict) -> None:
        disk_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = disk_path.with_suffix(disk_path.suffix + ".tmp")
        tmp_path.write_text(
            json.dumps(payload, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp_path.replace(disk_path)

    def _disk_path(self, path: str, content: str) -> Path:
        assert self.cache_dir is not None
        digest = GraphCache.file_hash(self.key(path, content))
        return self.cache_dir / f"{digest}.json"

    def _merged_disk_path(self, key: str) -> Path:
        assert self.cache_dir is not None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / "merged" / f"{digest}.json"


def graph_cache_for_scan() -> GraphCache[CodeGraph] | CodeGraphCache:
    """Return the configured graph cache backend for a scan."""
    from ....config.constants import MCPScannerConstants

    cache_dir = MCPScannerConstants.CODE_GRAPH_CACHE_DIR.strip()
    if cache_dir:
        return CodeGraphCache(cache_dir=Path(cache_dir))
    return GraphCache[CodeGraph](version=GRAPH_EXTRACTOR_VERSION)
