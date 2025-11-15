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

"""Dataflow analysis framework."""

import ast
from typing import Any, Generic, TypeVar

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser

T = TypeVar("T")


class CFGNode:
    """Control Flow Graph node."""

    def __init__(self, node_id: int, ast_node: Any, label: str = "") -> None:
        """Initialize CFG node.

        Args:
            node_id: Unique node ID
            ast_node: Associated AST node
            label: Optional label
        """
        self.id = node_id
        self.ast_node = ast_node
        self.label = label
        self.predecessors: list[CFGNode] = []
        self.successors: list[CFGNode] = []

    def __repr__(self) -> str:
        """String representation."""
        return f"CFGNode({self.id}, {self.label})"


class ControlFlowGraph:
    """Control Flow Graph."""

    def __init__(self) -> None:
        """Initialize CFG."""
        self.nodes: list[CFGNode] = []
        self.entry: CFGNode | None = None
        self.exit: CFGNode | None = None
        self._node_counter = 0

    def create_node(self, ast_node: Any, label: str = "") -> CFGNode:
        """Create a new CFG node.

        Args:
            ast_node: AST node
            label: Optional label

        Returns:
            New CFG node
        """
        node = CFGNode(self._node_counter, ast_node, label)
        self._node_counter += 1
        self.nodes.append(node)
        return node

    def add_edge(self, from_node: CFGNode, to_node: CFGNode) -> None:
        """Add an edge between two nodes.

        Args:
            from_node: Source node
            to_node: Target node
        """
        from_node.successors.append(to_node)
        to_node.predecessors.append(from_node)

    def get_successors(self, node: CFGNode) -> list[CFGNode]:
        """Get successor nodes.

        Args:
            node: CFG node

        Returns:
            List of successor nodes
        """
        return node.successors

    def get_predecessors(self, node: CFGNode) -> list[CFGNode]:
        """Get predecessor nodes.

        Args:
            node: CFG node

        Returns:
            List of predecessor nodes
        """
        return node.predecessors


class DataFlowAnalyzer(Generic[T]):
    """Generic dataflow analysis framework."""

    def __init__(self, analyzer: BaseParser) -> None:
        """Initialize dataflow analyzer.

        Args:
            analyzer: Language-specific analyzer
        """
        self.analyzer = analyzer
        self.cfg: ControlFlowGraph | None = None
        self.in_facts: dict[int, T] = {}
        self.out_facts: dict[int, T] = {}

    def build_cfg(self) -> ControlFlowGraph:
        """Build Control Flow Graph from AST.

        Returns:
            Control Flow Graph
        """
        ast_root = self.analyzer.get_ast()
        cfg = ControlFlowGraph()

        if isinstance(self.analyzer, PythonParser):
            self._build_python_cfg(ast_root, cfg)

        self.cfg = cfg
        return cfg

    def _build_python_cfg(self, node: ast.AST, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for Python AST.

        Args:
            node: Python AST node
            cfg: Control Flow Graph

        Returns:
            Last CFG node created
        """
        if isinstance(node, ast.Module):
            entry = cfg.create_node(node, "entry")
            cfg.entry = entry

            current = entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(current, next_node)
                current = next_node

            exit_node = cfg.create_node(node, "exit")
            cfg.exit = exit_node
            cfg.add_edge(current, exit_node)

            return exit_node
        
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Build CFG for function body
            entry = cfg.create_node(node, "func_entry")
            if not cfg.entry:
                cfg.entry = entry

            current = entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(current, next_node)
                current = next_node

            exit_node = cfg.create_node(node, "func_exit")
            if not cfg.exit:
                cfg.exit = exit_node
            cfg.add_edge(current, exit_node)

            return exit_node

        elif isinstance(node, ast.If):
            cond_node = cfg.create_node(node.test, "if_cond")

            then_entry = cfg.create_node(node, "then_entry")
            cfg.add_edge(cond_node, then_entry)

            then_current = then_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(then_current, next_node)
                then_current = next_node

            if node.orelse:
                else_entry = cfg.create_node(node, "else_entry")
                cfg.add_edge(cond_node, else_entry)

                else_current = else_entry
                for stmt in node.orelse:
                    next_node = self._build_python_cfg(stmt, cfg)
                    cfg.add_edge(else_current, next_node)
                    else_current = next_node

                merge = cfg.create_node(node, "if_merge")
                cfg.add_edge(then_current, merge)
                cfg.add_edge(else_current, merge)
                return merge
            else:
                merge = cfg.create_node(node, "if_merge")
                cfg.add_edge(then_current, merge)
                cfg.add_edge(cond_node, merge)
                return merge

        elif isinstance(node, ast.While):
            cond_node = cfg.create_node(node.test, "while_cond")

            body_entry = cfg.create_node(node, "while_body")
            cfg.add_edge(cond_node, body_entry)

            body_current = body_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(body_current, next_node)
                body_current = next_node

            cfg.add_edge(body_current, cond_node)

            exit_node = cfg.create_node(node, "while_exit")
            cfg.add_edge(cond_node, exit_node)

            return exit_node

        elif isinstance(node, ast.For):
            iter_node = cfg.create_node(node.iter, "for_iter")

            body_entry = cfg.create_node(node, "for_body")
            cfg.add_edge(iter_node, body_entry)

            body_current = body_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(body_current, next_node)
                body_current = next_node

            cfg.add_edge(body_current, iter_node)

            exit_node = cfg.create_node(node, "for_exit")
            cfg.add_edge(iter_node, exit_node)

            return exit_node

        else:
            return cfg.create_node(node, type(node).__name__)

    def analyze(self, initial_fact: T, forward: bool = True) -> None:
        """Run dataflow analysis using worklist algorithm.

        Args:
            initial_fact: Initial dataflow fact
            forward: True for forward analysis, False for backward
        """
        if not self.cfg:
            self.build_cfg()

        if not self.cfg:
            return

        for node in self.cfg.nodes:
            self.in_facts[node.id] = initial_fact
            self.out_facts[node.id] = initial_fact

        worklist = list(self.cfg.nodes)
        in_worklist = {node.id for node in worklist}
        
        iteration_count = 0
        max_iterations = len(self.cfg.nodes) * 100  # Safety limit

        while worklist:
            iteration_count += 1
            
            # Safety check to prevent infinite loops
            if iteration_count > max_iterations:
                import logging
                logging.getLogger(__name__).warning(f"Dataflow analysis exceeded max iterations ({max_iterations}), stopping early")
                break
            
            node = worklist.pop(0)
            in_worklist.discard(node.id)

            if forward:
                pred_facts = [self.out_facts[pred.id] for pred in node.predecessors]
                if pred_facts:
                    in_fact = self.merge(pred_facts)
                else:
                    in_fact = initial_fact

                self.in_facts[node.id] = in_fact

                out_fact = self.transfer(node, in_fact)

                if out_fact != self.out_facts[node.id]:
                    self.out_facts[node.id] = out_fact

                    for succ in node.successors:
                        if succ.id not in in_worklist:
                            worklist.append(succ)
                            in_worklist.add(succ.id)
            else:
                succ_facts = [self.in_facts[succ.id] for succ in node.successors]
                if succ_facts:
                    out_fact = self.merge(succ_facts)
                else:
                    out_fact = initial_fact

                self.out_facts[node.id] = out_fact

                in_fact = self.transfer(node, out_fact)

                if in_fact != self.in_facts[node.id]:
                    self.in_facts[node.id] = in_fact

                    for pred in node.predecessors:
                        if pred.id not in in_worklist:
                            worklist.append(pred)
                            in_worklist.add(pred.id)

    def transfer(self, node: CFGNode, in_fact: T) -> T:
        """Transfer function for dataflow analysis.

        Args:
            node: CFG node
            in_fact: Input dataflow fact

        Returns:
            Output dataflow fact
        """
        return in_fact

    def merge(self, facts: list[T]) -> T:
        """Merge multiple dataflow facts.

        Args:
            facts: List of facts to merge

        Returns:
            Merged fact
        """
        if facts:
            return facts[0]
        raise NotImplementedError("merge must be implemented by subclass")

    def get_reaching_definitions(self, node: CFGNode) -> T:
        """Get reaching definitions at a node.

        Args:
            node: CFG node

        Returns:
            Dataflow fact
        """
        return self.in_facts.get(node.id, self.in_facts.get(0))  # type: ignore
