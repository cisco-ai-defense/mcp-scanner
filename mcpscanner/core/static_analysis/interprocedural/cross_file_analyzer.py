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

"""Backwards-compatibility shim for the cross-file analyzer.

The original implementation in this module was a direct precursor to
:class:`CallGraphAnalyzer` and held a parallel, *unoptimised* copy of the
same data structures (no adjacency / reverse / short-name indices, no
reachability cache, ``O(N)`` linear scans inside resolution). The public
surface is identical, so to avoid drift we now re-export the optimised
versions from :mod:`call_graph_analyzer` under the original names.

External callers that imported ``CrossFileAnalyzer`` / ``CallGraph`` from
this path keep working unchanged and pick up the performance + correctness
improvements (memoised reachability, indexed lookups, deduped edges) for
free. New code should import from
``mcpscanner.core.static_analysis.interprocedural.call_graph_analyzer``
directly.
"""

from .call_graph_analyzer import CallGraph, CallGraphAnalyzer

# ``CrossFileAnalyzer`` is the legacy name — keep the alias so existing
# imports continue to resolve. Both classes share the same constructor and
# method set (``add_file``, ``_resolve_call_target``,
# ``get_reachable_functions``, ``analyze_parameter_flow_across_files``,
# etc.), so this is a transparent rename rather than a wrapper.
CrossFileAnalyzer = CallGraphAnalyzer

__all__ = ["CallGraph", "CrossFileAnalyzer", "CallGraphAnalyzer"]
