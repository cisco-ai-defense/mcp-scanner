# Copyright 2026 Cisco Systems, Inc. and its affiliates
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
"""Path-safety helpers used by directory-walking analyzers.

The behavioural code analyzer and the VirusTotal analyzer both walk a
user-supplied directory with ``Path.rglob`` and then read or hash each
matching file. By default ``Path.rglob`` matches symlinked files, and
``open()`` / ``Path.read_bytes()`` follow those links — so a hostile or
careless directory layout that contains a symlink to a file outside the
scan root would cause that external file to be ingested by the scanner
(and, with the VT analyzer's upload mode, exfiltrated to VirusTotal).

This module centralises the defence: resolve the scan root once, resolve
each candidate, and reject anything whose canonical location escapes the
root. Callers also get a single place to log the decision so audit trails
are consistent across analyzers.

The behaviour intentionally rejects symlinks whose target lies outside
the scan root rather than rejecting all symlinks — symlinks that stay
inside the project (e.g. ``node_modules/.bin``) are legitimate and would
otherwise produce false negatives for legitimate scans.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def safe_resolve_root(directory: str | os.PathLike) -> Path:
    """Resolve ``directory`` to an absolute, symlink-free canonical path.

    The result is what every per-file ``is_within_root`` check is measured
    against. ``strict=False`` lets us accept paths whose terminal component
    does not yet exist (some test fixtures rely on that), but the rest of
    the chain is still resolved.
    """
    return Path(directory).resolve(strict=False)


def is_within_root(candidate: Path, resolved_root: Path) -> bool:
    """Return ``True`` iff ``candidate`` resolves to a location inside
    ``resolved_root``.

    The check uses :py:meth:`Path.resolve` on the candidate so the answer
    reflects the *target* of any intervening symlinks, not the symlink
    name. ``resolved_root`` is expected to already be the output of
    :func:`safe_resolve_root` — we do not re-resolve it on every call to
    keep the per-file cost down on large trees.
    """
    try:
        resolved_candidate = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        # ``resolve()`` can raise on broken symlinks or on cycles; treat
        # both as "not safe to read" rather than propagating.
        return False

    if resolved_candidate == resolved_root:
        return True
    try:
        resolved_candidate.relative_to(resolved_root)
        return True
    except ValueError:
        return False


def filter_safe_paths(
    candidates,
    resolved_root: Path,
    *,
    audit_label: str = "scan",
) -> Tuple[list, int]:
    """Filter an iterable of ``Path`` candidates down to ones that stay
    inside ``resolved_root``.

    Returns ``(safe_paths, skipped_count)``. Each rejected candidate is
    logged at ``WARNING`` so an operator can see — after the fact — that
    a symlink escape was attempted on the directory they handed to the
    scanner. We deliberately do not log the symlink *target* at WARNING
    level: that target is the very file the attacker tried to exfiltrate,
    and echoing it into shared logs would defeat the defence. The target
    is only emitted at DEBUG, where local operators can opt in.
    """
    safe: list = []
    skipped = 0
    for candidate in candidates:
        if is_within_root(candidate, resolved_root):
            safe.append(candidate)
            continue

        skipped += 1
        try:
            target_repr: Optional[str] = str(candidate.resolve(strict=False))
        except Exception:
            target_repr = None

        logger.warning(
            "[%s] skipping symlink that escapes scan root: %s",
            audit_label,
            candidate,
        )
        if target_repr is not None:
            logger.debug(
                "[%s] escape target was: %s (root=%s)",
                audit_label,
                target_repr,
                resolved_root,
            )
    return safe, skipped


__all__ = ["safe_resolve_root", "is_within_root", "filter_safe_paths"]
