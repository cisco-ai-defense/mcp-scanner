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

"""Unified forward dataflow analysis that works with language-agnostic AST."""

from dataclasses import dataclass, field
from typing import Dict, List, Set

from ..cfg.unified_cfg_builder import UnifiedCFGBuilder
from ..taint.tracker import ShapeEnvironment, Taint, TaintStatus
from ..unified_ast import NodeType, UnifiedASTNode
from .constant_propagation import ConstantPropagationAnalysis
from .liveness_analysis import LivenessAnalyzer
from .reaching_definitions import ReachingDefinitionsAnalysis


@dataclass
class UnifiedFlowPath:
    """Represents a flow path from a parameter through the code."""
    
    parameter_name: str
    operations: List[Dict] = field(default_factory=list)
    reaches_calls: List[str] = field(default_factory=list)
    reaches_assignments: List[str] = field(default_factory=list)
    reaches_returns: bool = False
    reaches_external: bool = False


@dataclass
class UnifiedForwardFlowFact:
    """Dataflow fact for unified forward flow analysis."""
    
    parameter_flows: Dict[str, UnifiedFlowPath] = field(default_factory=dict)
    shape_env: ShapeEnvironment = field(default_factory=ShapeEnvironment)
    
    def copy(self) -> "UnifiedForwardFlowFact":
        """Create a copy of this fact."""
        new_fact = UnifiedForwardFlowFact()
        for param, flow in self.parameter_flows.items():
            new_fact.parameter_flows[param] = UnifiedFlowPath(
                parameter_name=flow.parameter_name,
                operations=flow.operations.copy(),
                reaches_calls=flow.reaches_calls.copy(),
                reaches_assignments=flow.reaches_assignments.copy(),
                reaches_returns=flow.reaches_returns,
                reaches_external=flow.reaches_external,
            )
        new_fact.shape_env = self.shape_env  # ShapeEnvironment is immutable-ish
        return new_fact
    
    def merge(self, other: "UnifiedForwardFlowFact") -> "UnifiedForwardFlowFact":
        """Merge two facts."""
        merged = UnifiedForwardFlowFact()
        
        # Merge parameter flows
        all_params = set(self.parameter_flows.keys()) | set(other.parameter_flows.keys())
        for param in all_params:
            self_flow = self.parameter_flows.get(param)
            other_flow = other.parameter_flows.get(param)
            
            if self_flow and other_flow:
                # Merge flows
                merged_flow = UnifiedFlowPath(
                    parameter_name=param,
                    operations=self_flow.operations + other_flow.operations,
                    reaches_calls=list(set(self_flow.reaches_calls + other_flow.reaches_calls)),
                    reaches_assignments=list(set(self_flow.reaches_assignments + other_flow.reaches_assignments)),
                    reaches_returns=self_flow.reaches_returns or other_flow.reaches_returns,
                    reaches_external=self_flow.reaches_external or other_flow.reaches_external,
                )
                merged.parameter_flows[param] = merged_flow
            elif self_flow:
                merged.parameter_flows[param] = self_flow
            elif other_flow:
                merged.parameter_flows[param] = other_flow
        
        # Merge shape environments
        merged.shape_env = self.shape_env.merge(other.shape_env)
        
        return merged


class UnifiedForwardDataflowAnalysis:
    """Forward dataflow analysis for unified AST (language-agnostic).
    
    Tracks how parameters flow through the code, recording all operations
    they're involved in. Works with Python, JavaScript, and TypeScript.
    """
    
    def __init__(self, unified_ast: UnifiedASTNode, parameter_names: List[str]):
        """Initialize forward flow tracker.
        
        Args:
            unified_ast: Unified AST node (typically a FUNCTION)
            parameter_names: Names of function parameters to track
        """
        self.unified_ast = unified_ast
        self.parameter_names = parameter_names
        self.all_flows: List[UnifiedFlowPath] = []
        
        # Run all dataflow analyses
        # 1. Constant propagation - find constant values
        self.const_prop = ConstantPropagationAnalysis(analyzer=None)
        self.const_prop.analyze_unified(unified_ast)
        
        # 2. Liveness analysis - find which variables are used
        self.liveness = LivenessAnalyzer(analyzer=None, parameter_names=parameter_names)
        self.live_vars = self.liveness.analyze_unified(unified_ast, parameter_names)
        
        # 3. Reaching definitions - find where variables are defined
        self.reaching_defs = ReachingDefinitionsAnalysis(analyzer=None, parameter_names=parameter_names)
        self.definitions = self.reaching_defs.analyze_unified(unified_ast, parameter_names)
        
        # Build CFG
        self.cfg_builder = UnifiedCFGBuilder()
        self.cfg = self.cfg_builder.build_cfg(unified_ast)
        
        # Dataflow facts
        self.in_facts: Dict[int, UnifiedForwardFlowFact] = {}
        self.out_facts: Dict[int, UnifiedForwardFlowFact] = {}
    
    def analyze_forward_flows(self) -> List[UnifiedFlowPath]:
        """Run forward flow analysis.
        
        Returns:
            List of flow paths from each parameter
        """
        if not self.cfg or not self.cfg.entry:
            return []
        
        # Initialize entry fact with parameters as taint sources
        entry_fact = UnifiedForwardFlowFact()
        for param_name in self.parameter_names:
            entry_fact.parameter_flows[param_name] = UnifiedFlowPath(parameter_name=param_name)
            entry_fact.shape_env.set_taint(param_name, Taint(status=TaintStatus.TAINTED))
        
        self.in_facts[self.cfg.entry.id] = entry_fact
        self.out_facts[self.cfg.entry.id] = entry_fact.copy()
        
        # Worklist algorithm
        worklist = [self.cfg.entry]
        visited = set()
        
        while worklist:
            node = worklist.pop(0)
            
            if node.id in visited:
                continue
            visited.add(node.id)
            
            # Get input fact
            in_fact = self.in_facts.get(node.id, UnifiedForwardFlowFact())
            
            # Apply transfer function
            out_fact = self._transfer(node, in_fact)
            self.out_facts[node.id] = out_fact
            
            # Propagate to successors
            for succ in node.successors:
                if succ.id not in self.in_facts:
                    self.in_facts[succ.id] = out_fact.copy()
                else:
                    # Merge with existing fact
                    self.in_facts[succ.id] = self.in_facts[succ.id].merge(out_fact)
                
                if succ not in visited:
                    worklist.append(succ)
        
        # Collect flows from exit node
        self._collect_flows()
        
        return self.all_flows
    
    def _transfer(self, cfg_node, fact: UnifiedForwardFlowFact) -> UnifiedForwardFlowFact:
        """Transfer function for a CFG node.
        
        Args:
            cfg_node: CFG node
            fact: Input dataflow fact
            
        Returns:
            Output dataflow fact
        """
        new_fact = fact.copy()
        node = cfg_node.ast_node
        
        if not isinstance(node, UnifiedASTNode):
            return new_fact
        
        # Handle different node types
        if node.type == NodeType.ASSIGNMENT:
            self._handle_assignment(node, new_fact)
        elif node.type == NodeType.CALL:
            self._handle_call(node, new_fact)
        elif node.type == NodeType.RETURN:
            self._handle_return(node, new_fact)
        elif node.type == NodeType.AWAIT:
            self._handle_await(node, new_fact)
        else:
            # For any other node type, recursively search for calls
            self._find_calls_in_node(node, new_fact)
        
        return new_fact
    
    def _handle_assignment(self, node: UnifiedASTNode, fact: UnifiedForwardFlowFact) -> None:
        """Handle assignment statement.
        
        Args:
            node: Assignment node
            fact: Dataflow fact to update
        """
        target_name = node.name
        if not target_name or target_name == "<unknown>":
            return
        
        # Check if RHS uses any tracked parameters
        for param_name in self.parameter_names:
            if self._expr_uses_param(node, param_name, fact):
                # Record assignment
                if param_name in fact.parameter_flows:
                    fact.parameter_flows[param_name].reaches_assignments.append(target_name)
                    fact.parameter_flows[param_name].operations.append({
                        "type": "assignment",
                        "target": target_name,
                        "line": node.location.line if node.location else 0,
                    })
                
                # Propagate taint to target
                fact.shape_env.set_taint(target_name, Taint(status=TaintStatus.TAINTED))
                break  # Only need to mark once
        
        # ALSO: Check if RHS uses any tainted variable (transitive taint)
        # This handles cases like: x = param; y = x; z = y;
        if not fact.shape_env.get_taint(target_name).is_tainted():
            # Check node value/metadata for tainted variables
            rhs_text = ""
            if hasattr(node, 'value') and node.value:
                rhs_text = str(node.value)
            if node.metadata:
                rhs_text += str(node.metadata)
            
            # Check if any tainted variable appears in RHS
            for var_name in fact.shape_env.shapes:
                if fact.shape_env.get_taint(var_name).is_tainted() and var_name in rhs_text:
                    # Propagate taint transitively
                    fact.shape_env.set_taint(target_name, Taint(status=TaintStatus.TAINTED))
                    # Also record this for all parameters that tainted the source variable
                    for param_name in self.parameter_names:
                        if param_name in fact.parameter_flows:
                            if var_name in fact.parameter_flows[param_name].reaches_assignments:
                                fact.parameter_flows[param_name].reaches_assignments.append(target_name)
                                fact.parameter_flows[param_name].operations.append({
                                    "type": "assignment",
                                    "target": target_name,
                                    "line": node.location.line if node.location else 0,
                                })
                    break
        
        # Also check for calls within the assignment (recursively)
        self._find_calls_in_node(node, fact)
    
    def _handle_call(self, node: UnifiedASTNode, fact: UnifiedForwardFlowFact) -> None:
        """Handle function call.
        
        Args:
            node: Call node
            fact: Dataflow fact to update
        """
        call_name = node.name or "<unknown>"
        
        # Check if any arguments use tracked parameters
        for param_name in self.parameter_names:
            if self._expr_uses_param(node, param_name, fact):
                if param_name in fact.parameter_flows:
                    fact.parameter_flows[param_name].reaches_calls.append(call_name)
                    fact.parameter_flows[param_name].operations.append({
                        "type": "function_call",
                        "function": call_name,
                        "line": node.location.line if node.location else 0,
                    })
                    
                    # Check for specific dangerous patterns
                    if self._is_potentially_dangerous_call(call_name):
                        fact.parameter_flows[param_name].reaches_external = True
    
    def _handle_return(self, node: UnifiedASTNode, fact: UnifiedForwardFlowFact) -> None:
        """Handle return statement.
        
        Args:
            node: Return node
            fact: Dataflow fact to update
        """
        # Check if return value uses any tracked parameters
        for param_name in self.parameter_names:
            if self._expr_uses_param(node, param_name, fact):
                if param_name in fact.parameter_flows:
                    fact.parameter_flows[param_name].reaches_returns = True
                    fact.parameter_flows[param_name].operations.append({
                        "type": "return",
                        "line": node.location.line if node.location else 0,
                    })
    
    def _handle_await(self, node: UnifiedASTNode, fact: UnifiedForwardFlowFact) -> None:
        """Handle await expression.
        
        Args:
            node: Await node
            fact: Dataflow fact to update
        """
        # Check if awaited expression uses any tracked parameters
        for param_name in self.parameter_names:
            if self._expr_uses_param(node, param_name, fact):
                if param_name in fact.parameter_flows:
                    fact.parameter_flows[param_name].operations.append({
                        "type": "await",
                        "line": node.location.line if node.location else 0,
                    })
    
    def _expr_uses_param(self, node: UnifiedASTNode, param_name: str, fact: UnifiedForwardFlowFact) -> bool:
        """Check if an expression uses a parameter.
        
        Args:
            node: Expression node
            param_name: Parameter name to check
            fact: Current dataflow fact
            
        Returns:
            True if expression uses the parameter
        """
        # Check if node itself is the parameter
        if node.type == NodeType.IDENTIFIER and node.name == param_name:
            return True
        
        # FALLBACK: Check if node's name or value contains the parameter
        # This helps with languages (like Rust) that don't create IDENTIFIER nodes
        if node.name and param_name in str(node.name):
            return True
        if hasattr(node, 'value') and node.value and param_name in str(node.value):
            return True
        
        # Check metadata for arguments that might contain the parameter or tainted variables
        if node.metadata and 'arguments' in node.metadata:
            for arg in node.metadata['arguments']:
                arg_str = str(arg)
                # Check if argument contains the parameter directly
                if param_name in arg_str:
                    return True
                # Check if argument contains any tainted variable
                for var_name in fact.shape_env.shapes:
                    if fact.shape_env.get_taint(var_name).is_tainted() and var_name in arg_str:
                        return True
        
        # Check if node's name contains any tainted variable (for calls like "client.post(data)")
        if node.name:
            node_name_str = str(node.name)
            for var_name in fact.shape_env.shapes:
                if fact.shape_env.get_taint(var_name).is_tainted() and var_name in node_name_str:
                    return True
        
        # Check if any tainted variable is used in children
        for child in node.children:
            if child.type == NodeType.IDENTIFIER:
                if fact.shape_env.get_taint(child.name).is_tainted():
                    return True
            
            # Recurse
            if self._expr_uses_param(child, param_name, fact):
                return True
        
        return False
    
    def _is_potentially_dangerous_call(self, call_name: str) -> bool:
        """Check if a call might be dangerous (network, file I/O, etc.).
        
        This is a heuristic - LLM will make final determination.
        
        Args:
            call_name: Function call name
            
        Returns:
            True if potentially dangerous
        """
        dangerous_patterns = [
            'fetch', 'http', 'request', 'axios',  # Network
            'exec', 'eval', 'spawn', 'system',    # Code execution
            'write', 'read', 'open', 'unlink',    # File I/O
            'post', 'get', 'put', 'delete',       # HTTP methods
        ]
        
        call_lower = call_name.lower()
        return any(pattern in call_lower for pattern in dangerous_patterns)
    
    def _find_calls_in_node(self, node: UnifiedASTNode, fact: UnifiedForwardFlowFact) -> None:
        """Recursively find all function calls in a node.
        
        Args:
            node: Node to search
            fact: Dataflow fact to update
        """
        # Check if this node is a call
        if node.type == NodeType.CALL:
            self._handle_call(node, fact)
        
        # Recursively check children
        for child in node.children:
            self._find_calls_in_node(child, fact)
    
    def _collect_flows(self) -> None:
        """Collect all flows from analysis results."""
        if not self.cfg or not self.cfg.exit:
            return
        
        # Get flows at exit node
        exit_fact = self.out_facts.get(self.cfg.exit.id)
        if exit_fact:
            for param_name, flow in exit_fact.parameter_flows.items():
                self.all_flows.append(flow)
