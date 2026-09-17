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

"""Deduplication that does not scramble order.

``list(set(xs))`` is the obvious way to dedupe and the wrong one here.
Python randomizes string hashing per process, so the resulting order
varies between runs of the same scan. That shows up two ways: report
fields differ for identical input, making two scans impossible to diff,
and any `list(set(xs))[:n]` silently changes *which* n items survive, so
evidence reaching an LLM prompt is not the same twice.
"""

from typing import Hashable, Iterable, List, TypeVar

T = TypeVar("T", bound=Hashable)


def dedupe(items: Iterable[T]) -> List[T]:
    """Drop duplicates, keeping first-seen order."""
    seen = set()
    result: List[T] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def union(*iterables: Iterable[T]) -> List[T]:
    """Concatenate and dedupe, keeping first-seen order across all inputs."""
    return dedupe(item for iterable in iterables for item in iterable)
