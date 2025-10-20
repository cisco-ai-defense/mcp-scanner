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

"""Analysis modules for dataflow, taint, and constant propagation."""

from .available_exprs import AvailableExpressionsAnalyzer, AvailableExprsFact
from .constant_prop import ConstantPropagator, SymbolicValue, ValueKind
from .cross_file import CrossFileAnalyzer, CallGraph
from .dataflow import CFGNode, ControlFlowGraph, DataFlowAnalyzer
from .forward_tracker import ForwardFlowTracker, FlowPath, ForwardFlowFact
from .liveness import LivenessAnalyzer, LivenessFact
from .naming import NameResolver, Scope
from .reaching_defs import ReachingDefinitionsAnalyzer, Definition, ReachingDefsFact
from .taint_shape import (
    ShapeEnvironment,
    SourceTrace,
    Taint,
    TaintShape,
    TaintStatus,
)
from .typing import TypeAnalyzer, Type, TypeKind

__all__ = [
    "AvailableExpressionsAnalyzer",
    "AvailableExprsFact",
    "CFGNode",
    "ControlFlowGraph",
    "CrossFileAnalyzer",
    "CallGraph",
    "DataFlowAnalyzer",
    "ForwardFlowTracker",
    "FlowPath",
    "ForwardFlowFact",
    "LivenessAnalyzer",
    "LivenessFact",
    "NameResolver",
    "Scope",
    "ReachingDefinitionsAnalyzer",
    "Definition",
    "ReachingDefsFact",
    "ConstantPropagator",
    "SymbolicValue",
    "ValueKind",
    "ShapeEnvironment",
    "SourceTrace",
    "Taint",
    "TaintShape",
    "TaintStatus",
    "TypeAnalyzer",
    "Type",
    "TypeKind",
]
