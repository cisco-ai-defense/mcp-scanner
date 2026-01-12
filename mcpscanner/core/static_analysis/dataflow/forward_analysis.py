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

"""Forward dataflow tracker for MCP entry points.

This module implements the REVERSED approach:
- Start from MCP entry point parameters (sources)
- Track ALL paths forward (no predefined sinks)
- Capture complete behavior for LLM analysis
"""

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from ..cfg.builder import CFGNode, DataFlowAnalyzer
from ..taint.tracker import ShapeEnvironment, Taint, TaintStatus
from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser


@dataclass
class FlowPath:
    """Represents a complete flow path from parameter."""
    parameter_name: str
    operations: List[Dict[str, Any]] = field(default_factory=list)
    reaches_calls: List[str] = field(default_factory=list)
    reaches_assignments: List[str] = field(default_factory=list)
    reaches_returns: bool = False
    reaches_external: bool = False  # Network, file, subprocess
    
    def copy(self) -> "FlowPath":
        """Create a deep copy of the flow path."""
        return FlowPath(
            parameter_name=self.parameter_name,
            operations=self.operations.copy(),
            reaches_calls=self.reaches_calls.copy(),
            reaches_assignments=self.reaches_assignments.copy(),
            reaches_returns=self.reaches_returns,
            reaches_external=self.reaches_external
        )


@dataclass
class ForwardFlowFact:
    """Dataflow fact tracking parameter flows."""
    shape_env: ShapeEnvironment = field(default_factory=ShapeEnvironment)
    parameter_flows: Dict[str, FlowPath] = field(default_factory=dict)
    
    def copy(self) -> "ForwardFlowFact":
        """Create a deep copy.
        
        Deep copies parameter_flows to prevent aliasing issues where mutations
        to out_fact affect in_fact and other facts.
        """
        return ForwardFlowFact(
            shape_env=self.shape_env.copy(),
            parameter_flows={k: v.copy() for k, v in self.parameter_flows.items()},
        )
    
    def __eq__(self, other: object) -> bool:
        """Check equality.
        
        Compares both shape_env and parameter_flows for proper fixpoint detection.
        """
        if not isinstance(other, ForwardFlowFact):
            return False
        
        if self.shape_env != other.shape_env:
            return False
        
        # Check parameter_flows keys
        if set(self.parameter_flows.keys()) != set(other.parameter_flows.keys()):
            return False
        
        # Compare flow paths (simplified comparison - check if same operations reached)
        for param in self.parameter_flows:
            self_flow = self.parameter_flows[param]
            other_flow = other.parameter_flows[param]
            
            if (len(self_flow.operations) != len(other_flow.operations) or
                set(self_flow.reaches_calls) != set(other_flow.reaches_calls) or
                self_flow.reaches_returns != other_flow.reaches_returns or
                self_flow.reaches_external != other_flow.reaches_external):
                return False
        
        return True


class ForwardDataflowAnalysis(DataFlowAnalyzer[ForwardFlowFact]):
    """Track all forward flows from MCP entry point parameters.
    
    This is the REVERSED approach:
    - Parameters are sources (untrusted input)
    - Track ALL operations parameters flow through
    - No predefined sinks - capture everything
    """

    def __init__(self, analyzer: BaseParser, parameter_names: List[str]):
        """Initialize forward flow tracker.

        Args:
            analyzer: Language-specific analyzer
            parameter_names: Names of function parameters to track
        """
        super().__init__(analyzer)
        self.parameter_names = parameter_names
        self.all_flows: List[FlowPath] = []

    def analyze_forward_flows(self) -> List[FlowPath]:
        """Run forward flow analysis from parameters.

        Returns:
            List of all flow paths from parameters
        """
        self.build_cfg()
        
        # Initialize: mark all parameters as tainted with unique labels
        initial_fact = ForwardFlowFact()
        for param_name in self.parameter_names:
            # Add unique label per parameter for source-sensitive tracking
            taint = Taint(status=TaintStatus.TAINTED)
            taint.add_label(f"param:{param_name}")  # Unique label per parameter
            initial_fact.shape_env.set_taint(param_name, taint)
            initial_fact.parameter_flows[param_name] = FlowPath(parameter_name=param_name)
        
        self.analyze(initial_fact, forward=True)
        
        # Collect all flows
        self._collect_flows()
        
        return self.all_flows

    def transfer(self, node: CFGNode, in_fact: ForwardFlowFact) -> ForwardFlowFact:
        """Transfer function tracking parameter flows.

        Args:
            node: CFG node
            in_fact: Input flow fact

        Returns:
            Output flow fact
        """
        out_fact = in_fact.copy()
        ast_node = node.ast_node

        if isinstance(self.analyzer, PythonParser):
            self._transfer_python(ast_node, out_fact)

        return out_fact

    def _transfer_python(self, node: ast.AST, fact: ForwardFlowFact) -> None:
        """Transfer function for Python nodes.

        Args:
            node: Python AST node
            fact: Flow fact to update
        """
        # Track assignments
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # Check if RHS contains tracked parameters
                    rhs_taint = self._eval_expr_taint(node.value, fact)
                    
                    if rhs_taint.is_tainted():
                        # Propagate taint
                        fact.shape_env.set_taint(target.id, rhs_taint)
                        
                        # Track which parameters flow here
                        for param_name in self.parameter_names:
                            if self._expr_uses_var(node.value, param_name, fact):
                                if param_name in fact.parameter_flows:
                                    fact.parameter_flows[param_name].reaches_assignments.append(
                                        f"{target.id} = {ast.unparse(node.value)}"
                                    )
                                    fact.parameter_flows[param_name].operations.append({
                                        "type": "assignment",
                                        "target": target.id,
                                        "value": ast.unparse(node.value),
                                        "line": node.lineno if hasattr(node, "lineno") else 0,
                                    })
                                    
                                    # Check if RHS is a call to external operation
                                    if isinstance(node.value, ast.Call):
                                        call_name = self._get_call_name(node.value)
                                        fact.parameter_flows[param_name].reaches_calls.append(call_name)
                                        # LLM will determine if operations are dangerous
                    else:
                        # Clear taint
                        fact.shape_env.set_taint(target.id, Taint(status=TaintStatus.UNTAINTED))
        
        # Track function calls
        elif isinstance(node, ast.Call):
            call_name = self._get_call_name(node)
            
            # Check if any arguments contain tracked parameters
            for arg in node.args:
                arg_taint = self._eval_expr_taint(arg, fact)
                if arg_taint.is_tainted():
                    for param_name in self.parameter_names:
                        if self._expr_uses_var(arg, param_name, fact):
                            if param_name in fact.parameter_flows:
                                fact.parameter_flows[param_name].reaches_calls.append(call_name)
                                fact.parameter_flows[param_name].operations.append({
                                    "type": "function_call",
                                    "function": call_name,
                                    "argument": ast.unparse(arg),
                                    "line": node.lineno if hasattr(node, "lineno") else 0,
                                })
                                
                                # LLM will determine if operations are dangerous
        
        # Track returns
        elif isinstance(node, ast.Return):
            if node.value:
                ret_taint = self._eval_expr_taint(node.value, fact)
                if ret_taint.is_tainted():
                    for param_name in self.parameter_names:
                        if self._expr_uses_var(node.value, param_name, fact):
                            if param_name in fact.parameter_flows:
                                fact.parameter_flows[param_name].reaches_returns = True
                                fact.parameter_flows[param_name].operations.append({
                                    "type": "return",
                                    "value": ast.unparse(node.value),
                                    "line": node.lineno if hasattr(node, "lineno") else 0,
                                })

    def _eval_expr_taint(self, expr: ast.AST, fact: ForwardFlowFact) -> Taint:
        """Evaluate taint of an expression.

        Args:
            expr: Expression node
            fact: Current flow fact

        Returns:
            Taint of the expression
        """
        if isinstance(expr, ast.Name):
            return fact.shape_env.get_taint(expr.id)
        
        elif isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name):
                obj_name = expr.value.id
                field_name = expr.attr
                shape = fact.shape_env.get(obj_name)
                return shape.get_field(field_name)
            else:
                return self._eval_expr_taint(expr.value, fact)
        
        elif isinstance(expr, ast.Subscript):
            if isinstance(expr.value, ast.Name):
                arr_name = expr.value.id
                shape = fact.shape_env.get(arr_name)
                return shape.get_element()
            else:
                return self._eval_expr_taint(expr.value, fact)
        
        elif isinstance(expr, ast.Call):
            # Merge taint from all arguments
            result = Taint(status=TaintStatus.UNTAINTED)
            for arg in expr.args:
                arg_taint = self._eval_expr_taint(arg, fact)
                result = result.merge(arg_taint)
            return result
        
        elif isinstance(expr, ast.BinOp):
            left_taint = self._eval_expr_taint(expr.left, fact)
            right_taint = self._eval_expr_taint(expr.right, fact)
            return left_taint.merge(right_taint)
        
        elif isinstance(expr, ast.JoinedStr):
            result = Taint(status=TaintStatus.UNTAINTED)
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    taint = self._eval_expr_taint(value.value, fact)
                    result = result.merge(taint)
            return result
        
        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            result = Taint(status=TaintStatus.UNTAINTED)
            for elt in expr.elts:
                taint = self._eval_expr_taint(elt, fact)
                result = result.merge(taint)
            return result
        
        else:
            return Taint(status=TaintStatus.UNTAINTED)

    def _expr_uses_var(self, expr: ast.AST, var_name: str, fact: ForwardFlowFact) -> bool:
        """Check if expression uses a variable (directly or transitively).
        
        Uses source-sensitive tracking via taint labels to avoid false positives.
        Also checks structural shapes for per-field taints in objects/arrays.

        Args:
            expr: Expression node
            var_name: Variable name to check
            fact: Current flow fact

        Returns:
            True if expression uses the variable (with source sensitivity)
        """
        # Get the target variable's taint shape and labels
        target_shape = fact.shape_env.get(var_name)
        target_taint = target_shape.get_taint()
        target_labels = target_taint.labels if target_taint.is_tainted() else set()
        
        # Expected label for this parameter
        expected_label = f"param:{var_name}"
        
        for node in ast.walk(expr):
            if isinstance(node, ast.Name):
                # Direct reference
                if node.id == var_name:
                    return True
                
                # Check transitive dependencies with source sensitivity
                node_shape = fact.shape_env.get(node.id)
                node_taint = node_shape.get_taint()
                
                if node_taint.is_tainted():
                    # Check if this variable has the expected label
                    if expected_label in node_taint.labels:
                        return True
                    
                    # Also check if shares any labels with target (transitive)
                    if target_labels and node_taint.labels & target_labels:
                        return True
                    
                    # Check structural shapes for per-field taints
                    if node_shape.is_object:
                        for field_name, field_shape in node_shape.fields.items():
                            field_taint = field_shape.get_taint()
                            if expected_label in field_taint.labels:
                                return True
                    
                    if node_shape.is_array and node_shape.element_shape:
                        elem_taint = node_shape.element_shape.get_taint()
                        if expected_label in elem_taint.labels:
                            return True
        
        return False

    def _get_call_name(self, node: ast.Call) -> str:
        """Get function call name.

        Args:
            node: Call node

        Returns:
            Function name
        """
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ast.unparse(node.func)

    def _collect_flows(self) -> None:
        """Collect all flows from analysis results."""
        if not self.cfg or not self.cfg.exit:
            return
        
        # Get flows at exit node
        exit_fact = self.out_facts.get(self.cfg.exit.id)
        if exit_fact:
            for param_name, flow in exit_fact.parameter_flows.items():
                self.all_flows.append(flow)

    def merge(self, facts: List[ForwardFlowFact]) -> ForwardFlowFact:
        """Merge multiple flow facts.

        Args:
            facts: List of facts to merge

        Returns:
            Merged fact
        """
        if not facts:
            return ForwardFlowFact()
        
        if len(facts) == 1:
            return facts[0]
        
        result = facts[0].copy()
        
        for fact in facts[1:]:
            result.shape_env = result.shape_env.merge(fact.shape_env)
            
            # Merge parameter flows
            for param_name, flow in fact.parameter_flows.items():
                if param_name in result.parameter_flows:
                    # Merge operations
                    result.parameter_flows[param_name].operations.extend(flow.operations)
                    result.parameter_flows[param_name].reaches_calls.extend(flow.reaches_calls)
                    result.parameter_flows[param_name].reaches_assignments.extend(flow.reaches_assignments)
                    result.parameter_flows[param_name].reaches_returns = (
                        result.parameter_flows[param_name].reaches_returns or flow.reaches_returns
                    )
                    result.parameter_flows[param_name].reaches_external = (
                        result.parameter_flows[param_name].reaches_external or flow.reaches_external
                    )
                else:
                    result.parameter_flows[param_name] = flow
        
        return result
