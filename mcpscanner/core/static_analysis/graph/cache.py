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
        """Compute the SHA-256 hexadecimal digest of text content.
        
        Parameters:
        	content (str): The content to hash.
        
        Returns:
        	str: The content's SHA-256 hexadecimal digest.
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def key(self, path: str, content: str) -> str:
        """
        Build a cache key from the extractor version, file path, and content hash.
        
        Parameters:
            path (str): File path associated with the cached value.
            content (str): File content used to compute the content hash.
        
        Returns:
            str: The cache key.
        """
        return f"{self.version}:{path}:{self.file_hash(content)}"

    def get(self, path: str, content: str) -> T | None:
        """Retrieve the cached value for a file's path and content.
        
        Parameters:
            path (str): The file path used to identify the cache entry.
            content (str): The file content used to identify the cache entry.
        
        Returns:
            T | None: The cached value, or `None` if no matching entry exists.
        """
        return self._store.get(self.key(path, content))

    def put(self, path: str, content: str, value: T) -> None:
        """Store a value in the cache for the specified file content."""
        self._store[self.key(path, content)] = value

    def clear(self) -> None:
        """Clear all entries from the in-memory cache."""
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
        """
        Build a cache key from the file path and content.
        
        Parameters:
            path (str): The file path.
            content (str): The file content.
        
        Returns:
            str: The cache key for the file.
        """
        return self._memory.key(path, content)

    def get(self, path: str, content: str) -> CodeGraph | None:
        """Retrieve a cached code graph for the specified file content.
        
        Parameters:
            path (str): Path identifying the source file.
            content (str): Current source file content.
        
        Returns:
            CodeGraph | None: The cached graph, or `None` when no valid cached graph is available.
        """
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
        """Store a code graph in the in-memory cache and, when configured, persist it to disk."""
        self._memory.put(path, content, value)
        if self.cache_dir is None:
            return
        disk_path = self._disk_path(path, content)
        try:
            disk_path.parent.mkdir(parents=True, exist_ok=True)
            disk_path.write_text(
                json.dumps(value.to_dict(), separators=(",", ":")),
                encoding="utf-8",
            )
        except OSError:
            return

    def clear(self) -> None:
        """Clear all cached entries from memory."""
        self._memory.clear()

    def merged_key(self, language: str, files: dict[str, str]) -> str:
        """
        Create a cache key for a merged graph identified by language and file contents.
        
        Parameters:
        	language (str): The programming language of the merged graph.
        	files (dict[str, str]): A mapping of file paths to their source contents.
        
        Returns:
        	str: A cache key incorporating the extractor version, language, file paths, and content hashes.
        """
        parts = sorted(f"{path}:{GraphCache.file_hash(source)}" for path, source in files.items())
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
        return f"{self.version}:merged:{language}:{digest}"

    def get_merged(self, language: str, files: dict[str, str]) -> CodeGraph | None:
        """
        Retrieve a cached merged code graph for the specified language and files.
        
        Parameters:
            language (str): Programming language of the merged graph.
            files (dict[str, str]): File paths mapped to their contents.
        
        Returns:
            CodeGraph | None: The cached merged graph, or `None` if no valid cached graph exists.
        """
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
        """
        Store a merged code graph for the specified language and files.
        """
        key = self.merged_key(language, files)
        self._memory._store[key] = value
        if self.cache_dir is None:
            return
        disk_path = self._merged_disk_path(key)
        try:
            disk_path.parent.mkdir(parents=True, exist_ok=True)
            disk_path.write_text(
                json.dumps(value.to_dict(), separators=(",", ":")),
                encoding="utf-8",
            )
        except OSError:
            return

    def _disk_path(self, path: str, content: str) -> Path:
        """Build the disk path for a cached file graph entry.
        
        Parameters:
            path (str): Path identifying the source file.
            content (str): Source file content used to identify the cache entry.
        
        Returns:
            Path: Path to the cache entry's JSON file.
        """
        assert self.cache_dir is not None
        digest = GraphCache.file_hash(self.key(path, content))
        return self.cache_dir / f"{digest}.json"

    def _merged_disk_path(self, key: str) -> Path:
        """Build the disk path for a merged graph cache entry.
        
        Parameters:
            key (str): Complete cache key used to derive the filename.
        
        Returns:
            Path: Path to the merged graph cache file.
        """
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
