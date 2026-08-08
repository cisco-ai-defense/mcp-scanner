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

"""Source-tree discovery shared by the source-scanning code paths.

This module is deliberately dependency-light: it imports nothing that pulls
in an LLM SDK. The behavioural analyzer's module graph reaches ``litellm``,
which costs roughly 11 seconds and ~880 modules to import, so a no-LLM YARA
scan must not have to import it just to walk a directory.

Both :mod:`mcpscanner.core.source_scan` and the behavioural analyzer use the
definitions here, keeping one source of truth for which extensions count as
source and for symlink-escape filtering.
"""

from pathlib import Path
from typing import Dict, List, Set

from ..utils.path_safety import filter_safe_paths, safe_resolve_root

# Extension -> tree-sitter language name.
EXT_TO_TS_LANGUAGE: Dict[str, str] = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "c_sharp",
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".phtml": "php",
}

PYTHON_EXTENSIONS: Set[str] = {".py", ".pyw"}

# Directories never worth walking into: build artefacts and dependency trees.
_EXCLUDED_DIR_NAMES = frozenset({"__pycache__", "node_modules"})


def relative_parts(file_path: Path, root: Path) -> tuple[str, ...]:
    """Return ``file_path``'s path components relative to ``root``.

    Skip/hidden heuristics must only consider directories *inside* the
    scanned tree. Using the absolute ``Path.parts`` would also inspect
    ancestors of ``root`` (e.g. a hidden ``TMPDIR`` such as
    ``/Users/me/.cache/T/...``) and wrongly drop every file. Falls back to
    the absolute parts only if ``file_path`` is somehow not under ``root``.
    """
    try:
        return file_path.relative_to(root).parts
    except ValueError:  # pragma: no cover - rglob results stay under root
        return file_path.parts


def find_source_files(directory: str, *, audit_label: str = "scan") -> List[str]:
    """Find all supported source files under ``directory``.

    Supports Python, TypeScript, JavaScript, Go, Java, Kotlin, C#, Ruby,
    Rust, and PHP. Skips ``__pycache__``, ``node_modules`` and any
    dot-directory inside the scan root, then drops candidates whose
    resolved path escapes the root via a symlink.

    Args:
        directory: Directory path to search.
        audit_label: Label used when logging rejected symlink escapes.

    Returns:
        Sorted list of source file paths.
    """
    path = Path(directory)
    resolved_root = safe_resolve_root(directory)

    extensions = PYTHON_EXTENSIONS | set(EXT_TO_TS_LANGUAGE.keys())

    candidates: List[Path] = []
    for ext in extensions:
        for source_file in path.rglob(f"*{ext}"):
            rel_parts = relative_parts(source_file, path)
            if any(part in _EXCLUDED_DIR_NAMES for part in rel_parts):
                continue
            if any(part.startswith(".") for part in rel_parts):
                continue
            candidates.append(source_file)

    safe_candidates, _skipped = filter_safe_paths(
        candidates, resolved_root, audit_label=audit_label
    )
    return sorted(str(p) for p in safe_candidates)
