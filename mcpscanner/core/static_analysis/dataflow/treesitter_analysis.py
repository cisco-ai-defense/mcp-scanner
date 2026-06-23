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

"""Forward dataflow analysis for tree-sitter ASTs.

This module implements CFG-based forward dataflow analysis for all
tree-sitter supported languages, providing the same level of taint
tracking as the Python-specific ForwardDataflowAnalysis.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from tree_sitter import Node

from ..cfg.treesitter_builder import TreeSitterCFG, TreeSitterCFGBuilder, TSCFGNode
from ..taint.tracker import Taint, TaintStatus, TaintShape, ShapeEnvironment, SourceTrace


@dataclass
class TSFlowPath:
    """Represents a complete flow path from parameter."""
    
    parameter_name: str
    operations: List[Dict[str, Any]] = field(default_factory=list)
    reaches_calls: List[str] = field(default_factory=list)
    reaches_assignments: List[str] = field(default_factory=list)
    reaches_returns: bool = False
    reaches_external: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for FunctionContext."""
        return {
            "parameter_name": self.parameter_name,
            "operations": self.operations,
            "reaches_calls": self.reaches_calls,
            "reaches_assignments": self.reaches_assignments,
            "reaches_returns": self.reaches_returns,
            "reaches_external": self.reaches_external,
        }


@dataclass
class TSFlowFact:
    """Dataflow fact for tree-sitter analysis."""
    
    shape_env: ShapeEnvironment = field(default_factory=ShapeEnvironment)
    parameter_flows: Dict[str, TSFlowPath] = field(default_factory=dict)
    
    def copy(self) -> "TSFlowFact":
        """Create a deep copy."""
        return TSFlowFact(
            shape_env=self.shape_env.copy(),
            parameter_flows={k: TSFlowPath(
                parameter_name=v.parameter_name,
                operations=v.operations.copy(),
                reaches_calls=v.reaches_calls.copy(),
                reaches_assignments=v.reaches_assignments.copy(),
                reaches_returns=v.reaches_returns,
                reaches_external=v.reaches_external,
            ) for k, v in self.parameter_flows.items()},
        )
    
    def merge(self, other: "TSFlowFact") -> "TSFlowFact":
        """Merge two flow facts."""
        result = TSFlowFact(
            shape_env=self.shape_env.merge(other.shape_env),
            parameter_flows={},
        )
        
        all_params = set(self.parameter_flows.keys()) | set(other.parameter_flows.keys())
        for param in all_params:
            self_flow = self.parameter_flows.get(param)
            other_flow = other.parameter_flows.get(param)
            
            if self_flow and other_flow:
                result.parameter_flows[param] = TSFlowPath(
                    parameter_name=param,
                    operations=self_flow.operations + [op for op in other_flow.operations if op not in self_flow.operations],
                    reaches_calls=list(set(self_flow.reaches_calls) | set(other_flow.reaches_calls)),
                    reaches_assignments=list(set(self_flow.reaches_assignments) | set(other_flow.reaches_assignments)),
                    reaches_returns=self_flow.reaches_returns or other_flow.reaches_returns,
                    reaches_external=self_flow.reaches_external or other_flow.reaches_external,
                )
            elif self_flow:
                result.parameter_flows[param] = TSFlowPath(
                    parameter_name=param,
                    operations=self_flow.operations.copy(),
                    reaches_calls=self_flow.reaches_calls.copy(),
                    reaches_assignments=self_flow.reaches_assignments.copy(),
                    reaches_returns=self_flow.reaches_returns,
                    reaches_external=self_flow.reaches_external,
                )
            elif other_flow:
                result.parameter_flows[param] = TSFlowPath(
                    parameter_name=param,
                    operations=other_flow.operations.copy(),
                    reaches_calls=other_flow.reaches_calls.copy(),
                    reaches_assignments=other_flow.reaches_assignments.copy(),
                    reaches_returns=other_flow.reaches_returns,
                    reaches_external=other_flow.reaches_external,
                )
        
        return result


class TreeSitterDataflowAnalysis:
    """Forward dataflow analysis for tree-sitter ASTs.
    
    Performs CFG-based taint tracking from function parameters,
    tracking all paths forward to calls, assignments, and returns.
    """
    
    # External operation patterns by category
    FILE_FUNCS = {"open", "read", "write", "readFile", "writeFile", "readFileSync",
                  "writeFileSync", "fopen", "fread", "fwrite", "fclose", "file_get_contents",
                  "file_put_contents", "unlink", "rename", "mkdir", "rmdir", "Open", "Create"}
    FILE_MODULES = {"fs", "File", "os", "ioutil", "bufio", "pathlib", "shutil", "io"}
    
    NETWORK_FUNCS = {"fetch", "request", "get", "post", "put", "delete", "patch", "urlopen"}
    NETWORK_MODULES = {"http", "https", "axios", "request", "net", "socket",
                       "HttpClient", "WebClient", "urllib", "requests", "aiohttp", "curl"}
    
    SUBPROCESS_FUNCS = {"exec", "execSync", "spawn", "spawnSync", "system", "popen",
                        "shell_exec", "passthru", "proc_open", "Command", "run", "call"}
    SUBPROCESS_MODULES = {"child_process", "Process", "Runtime", "ProcessBuilder",
                          "subprocess", "Command", "exec", "os"}
    
    EVAL_FUNCS = {"eval", "Function", "compile", "instance_eval", "class_eval",
                  "module_eval", "exec", "assert_options"}
    
    def __init__(self, language: str, function_node: Node, param_names: List[str], source_bytes: bytes):
        """Initialize dataflow analysis.
        
        Args:
            language: Programming language
            function_node: Tree-sitter function AST node
            param_names: List of parameter names to track
            source_bytes: Source code bytes for text extraction
        """
        self.language = language
        self.function_node = function_node
        self.param_names = param_names
        self.source_bytes = source_bytes
        
        # Build CFG
        self.cfg_builder = TreeSitterCFGBuilder(language)
        self.cfg = self.cfg_builder.build(function_node)
        
        # Initialize dataflow facts
        self.facts: Dict[int, TSFlowFact] = {}
    
    def analyze(self) -> List[TSFlowPath]:
        """Perform forward dataflow analysis.
        
        Returns:
            List of FlowPath objects for each parameter
        """
        # Initialize entry fact with tainted parameters
        entry_fact = TSFlowFact()
        for param in self.param_names:
            taint = Taint(
                status=TaintStatus.TAINTED,
                labels={param},
                sources=[SourceTrace(source_pattern=param, call_site=None, labels={param})],
            )
            entry_fact.shape_env.set_taint(param, taint)
            entry_fact.parameter_flows[param] = TSFlowPath(parameter_name=param)
        
        if self.cfg.entry:
            self.facts[self.cfg.entry.node_id] = entry_fact
        
        # Worklist algorithm
        worklist = [self.cfg.entry] if self.cfg.entry else []
        visited = set()
        max_iterations = len(self.cfg.nodes) * 10  # Prevent infinite loops
        iterations = 0
        
        while worklist and iterations < max_iterations:
            iterations += 1
            node = worklist.pop(0)
            
            if node is None or node.node_id in visited:
                continue
            
            # Get input fact (merge from predecessors)
            in_fact = self._get_input_fact(node)
            
            # Transfer function
            out_fact = self._transfer(node, in_fact)
            
            # Check for changes
            old_fact = self.facts.get(node.node_id)
            if old_fact is None or self._facts_changed(old_fact, out_fact):
                self.facts[node.node_id] = out_fact
                worklist.extend(node.successors)
            
            visited.add(node.node_id)
        
        # Collect results from all nodes
        return self._collect_results()
    
    def _get_input_fact(self, node: TSCFGNode) -> TSFlowFact:
        """Get input fact by merging predecessor facts."""
        if not node.predecessors:
            return self.facts.get(node.node_id, TSFlowFact())
        
        result = None
        for pred in node.predecessors:
            pred_fact = self.facts.get(pred.node_id)
            if pred_fact:
                if result is None:
                    result = pred_fact.copy()
                else:
                    result = result.merge(pred_fact)
        
        return result or TSFlowFact()
    
    def _transfer(self, cfg_node: TSCFGNode, in_fact: TSFlowFact) -> TSFlowFact:
        """Transfer function for a CFG node."""
        out_fact = in_fact.copy()
        ast_node = cfg_node.ast_node
        
        # Process the AST node
        self._process_node(ast_node, out_fact)
        
        return out_fact
    
    def _process_node(self, node: Node, fact: TSFlowFact) -> None:
        """Process an AST node and update flow fact."""
        node_type = node.type
        
        # Handle assignments
        if node_type in ("assignment_expression", "variable_declarator", "short_var_declaration",
                        "lexical_declaration", "variable_declaration", "local_variable_declaration",
                        "property_declaration", "let_declaration", "assignment"):
            self._process_assignment(node, fact)
        
        # Handle function calls
        elif node_type in ("call_expression", "method_invocation", "function_call_expression",
                          "member_call_expression", "scoped_call_expression", "new_expression"):
            self._process_call(node, fact)
        
        # Handle returns
        elif node_type in ("return_statement", "return_expression", "return"):
            self._process_return(node, fact)
        
        # Recursively process children
        for child in node.children:
            self._process_node(child, fact)
    
    def _process_assignment(self, node: Node, fact: TSFlowFact) -> None:
        """Process an assignment and propagate taint."""
        target = node.child_by_field_name("left") or node.child_by_field_name("name")
        value = node.child_by_field_name("right") or node.child_by_field_name("value")
        
        if not target or not value:
            # Try to find target and value in children
            for child in node.children:
                if child.type == "identifier" and target is None:
                    target = child
                elif child.type not in ("=", "identifier", ":=", "let", "var", "const") and value is None:
                    value = child
        
        if target and value:
            target_name = self._get_node_text(target)
            value_taint = self._eval_taint(value, fact)
            
            if value_taint.is_tainted():
                # Propagate taint to target
                fact.shape_env.set_taint(target_name, value_taint)
                
                # Update flow paths
                for label in value_taint.labels:
                    if label in fact.parameter_flows:
                        flow = fact.parameter_flows[label]
                        if target_name not in flow.reaches_assignments:
                            flow.reaches_assignments.append(target_name)
                        flow.operations.append({
                            "type": "assignment",
                            "target": target_name,
                            "value": self._get_node_text(value)[:100],
                            "line": node.start_point[0] + 1,
                        })
    
    def _process_call(self, node: Node, fact: TSFlowFact) -> None:
        """Process a function call and track taint flow."""
        func = node.child_by_field_name("function") or node.child_by_field_name("name")
        args = node.child_by_field_name("arguments")
        
        if not func:
            return
        
        func_name = self._get_node_text(func)
        
        # Check if any argument is tainted
        if args:
            args_taint = self._eval_taint(args, fact)
            if args_taint.is_tainted():
                # Update flow paths
                for label in args_taint.labels:
                    if label in fact.parameter_flows:
                        flow = fact.parameter_flows[label]
                        if func_name not in flow.reaches_calls:
                            flow.reaches_calls.append(func_name)
                        flow.operations.append({
                            "type": "call",
                            "function": func_name,
                            "line": node.start_point[0] + 1,
                        })
                        
                        # Check for external operations
                        if self._is_external_call(func_name):
                            flow.reaches_external = True
    
    def _process_return(self, node: Node, fact: TSFlowFact) -> None:
        """Process a return statement."""
        # Get return value
        for child in node.children:
            if child.type not in ("return", ";", "keyword"):
                ret_taint = self._eval_taint(child, fact)
                if ret_taint.is_tainted():
                    for label in ret_taint.labels:
                        if label in fact.parameter_flows:
                            flow = fact.parameter_flows[label]
                            flow.reaches_returns = True
                            flow.operations.append({
                                "type": "return",
                                "value": self._get_node_text(child)[:100],
                                "line": node.start_point[0] + 1,
                            })
                break
    
    def _eval_taint(self, node: Node, fact: TSFlowFact) -> Taint:
        """Evaluate taint of an expression via AST traversal."""
        result = Taint()
        
        def visit(n: Node) -> Taint:
            node_taint = Taint()
            
            # Check identifiers
            if n.type == "identifier":
                var_name = self._get_node_text(n)
                # Check if it's a parameter
                if var_name in self.param_names:
                    node_taint = Taint(
                        status=TaintStatus.TAINTED,
                        labels={var_name},
                    )
                # Check taint environment
                elif var_name:
                    env_taint = fact.shape_env.get_taint(var_name)
                    if env_taint.is_tainted():
                        node_taint = env_taint
            
            # Merge taint from children
            for child in n.children:
                child_taint = visit(child)
                node_taint = node_taint.merge(child_taint)
            
            return node_taint
        
        return visit(node)
    
    def _is_external_call(self, func_name: str) -> bool:
        """Check if a function call is an external operation."""
        parts = func_name.replace("::", ".").split(".")
        name = parts[-1] if parts else func_name
        module = parts[0] if len(parts) > 1 else ""
        
        if name in self.FILE_FUNCS or module in self.FILE_MODULES:
            return True
        if name in self.NETWORK_FUNCS or module in self.NETWORK_MODULES:
            return True
        if name in self.SUBPROCESS_FUNCS or module in self.SUBPROCESS_MODULES:
            return True
        if name in self.EVAL_FUNCS:
            return True
        
        return False
    
    def _get_node_text(self, node: Node) -> str:
        """Get text content of a tree-sitter node."""
        try:
            return node.text.decode("utf-8") if node.text else ""
        except Exception:
            return ""
    
    def _facts_changed(self, old: TSFlowFact, new: TSFlowFact) -> bool:
        """Check if facts have changed (for fixpoint detection)."""
        # Simple comparison - check if any flow paths changed
        if set(old.parameter_flows.keys()) != set(new.parameter_flows.keys()):
            return True
        
        for param in old.parameter_flows:
            old_flow = old.parameter_flows[param]
            new_flow = new.parameter_flows[param]
            
            if (old_flow.reaches_returns != new_flow.reaches_returns or
                old_flow.reaches_external != new_flow.reaches_external or
                set(old_flow.reaches_calls) != set(new_flow.reaches_calls) or
                set(old_flow.reaches_assignments) != set(new_flow.reaches_assignments)):
                return True
        
        return False
    
    def _collect_results(self) -> List[TSFlowPath]:
        """Collect final flow paths from all facts."""
        # Merge all facts to get complete picture
        result_flows: Dict[str, TSFlowPath] = {
            param: TSFlowPath(parameter_name=param) for param in self.param_names
        }
        
        for fact in self.facts.values():
            for param, flow in fact.parameter_flows.items():
                if param in result_flows:
                    result = result_flows[param]
                    result.reaches_calls = list(set(result.reaches_calls) | set(flow.reaches_calls))
                    result.reaches_assignments = list(set(result.reaches_assignments) | set(flow.reaches_assignments))
                    result.reaches_returns = result.reaches_returns or flow.reaches_returns
                    result.reaches_external = result.reaches_external or flow.reaches_external
                    # Merge operations (avoid duplicates)
                    for op in flow.operations:
                        if op not in result.operations:
                            result.operations.append(op)
        
        return list(result_flows.values())
