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

from tree_sitter import Node

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser
from ..parser.typescript_parser import TypeScriptParser
from ..parser.kotlin_parser import KotlinParser
from ..parser.go_parser import GoParser

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
        elif isinstance(self.analyzer, TypeScriptParser):
            self._build_typescript_cfg(ast_root, cfg)
        elif isinstance(self.analyzer, KotlinParser):
            self._build_kotlin_cfg(ast_root, cfg)
        elif isinstance(self.analyzer, GoParser):
            self._build_go_cfg(ast_root, cfg)

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

    def _build_typescript_cfg(self, node: Node, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for TypeScript tree-sitter AST.

        Args:
            node: tree-sitter Node
            cfg: Control Flow Graph

        Returns:
            Last CFG node created
        """
        node_type = node.type
        
        # Program/Module entry point
        if node_type == 'program':
            entry = cfg.create_node(node, "entry")
            cfg.entry = entry
            
            current = entry
            for child in node.children:
                if child.type not in {'comment', '\n', ' '}:
                    next_node = self._build_typescript_cfg(child, cfg)
                    cfg.add_edge(current, next_node)
                    current = next_node
            
            exit_node = cfg.create_node(node, "exit")
            cfg.exit = exit_node
            cfg.add_edge(current, exit_node)
            
            return exit_node
        
        # Function declarations
        elif node_type in {'function_declaration', 'arrow_function', 'function_expression', 'method_definition'}:
            entry = cfg.create_node(node, "func_entry")
            if not cfg.entry:
                cfg.entry = entry
            
            # Find function body
            body = node.child_by_field_name('body')
            if body is None:
                for child in node.children:
                    if child.type == 'statement_block':
                        body = child
                        break
            
            current = entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_typescript_cfg(child, cfg)
                        cfg.add_edge(current, next_node)
                        current = next_node
            
            exit_node = cfg.create_node(node, "func_exit")
            if not cfg.exit:
                cfg.exit = exit_node
            cfg.add_edge(current, exit_node)
            
            return exit_node
        
        # If statements
        elif node_type == 'if_statement':
            condition = node.child_by_field_name('condition')
            cond_node = cfg.create_node(condition if condition else node, "if_cond")
            
            # Then branch
            consequence = node.child_by_field_name('consequence')
            then_entry = cfg.create_node(node, "then_entry")
            cfg.add_edge(cond_node, then_entry)
            
            then_current = then_entry
            if consequence:
                for child in consequence.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_typescript_cfg(child, cfg)
                        cfg.add_edge(then_current, next_node)
                        then_current = next_node
            
            # Else branch
            alternative = node.child_by_field_name('alternative')
            if alternative:
                else_entry = cfg.create_node(node, "else_entry")
                cfg.add_edge(cond_node, else_entry)
                
                else_current = else_entry
                # Handle else if vs else block
                if alternative.type == 'else_clause':
                    for child in alternative.children:
                        if child.type not in {'else', '{', '}', 'comment', '\n', ' '}:
                            next_node = self._build_typescript_cfg(child, cfg)
                            cfg.add_edge(else_current, next_node)
                            else_current = next_node
                else:
                    next_node = self._build_typescript_cfg(alternative, cfg)
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
        
        # While loops
        elif node_type == 'while_statement':
            condition = node.child_by_field_name('condition')
            cond_node = cfg.create_node(condition if condition else node, "while_cond")
            
            body = node.child_by_field_name('body')
            body_entry = cfg.create_node(node, "while_body")
            cfg.add_edge(cond_node, body_entry)
            
            body_current = body_entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_typescript_cfg(child, cfg)
                        cfg.add_edge(body_current, next_node)
                        body_current = next_node
            
            cfg.add_edge(body_current, cond_node)
            
            exit_node = cfg.create_node(node, "while_exit")
            cfg.add_edge(cond_node, exit_node)
            
            return exit_node
        
        # For loops (for, for...in, for...of)
        elif node_type in {'for_statement', 'for_in_statement', 'for_of_statement'}:
            iter_node = cfg.create_node(node, "for_iter")
            
            body = node.child_by_field_name('body')
            body_entry = cfg.create_node(node, "for_body")
            cfg.add_edge(iter_node, body_entry)
            
            body_current = body_entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_typescript_cfg(child, cfg)
                        cfg.add_edge(body_current, next_node)
                        body_current = next_node
            
            cfg.add_edge(body_current, iter_node)
            
            exit_node = cfg.create_node(node, "for_exit")
            cfg.add_edge(iter_node, exit_node)
            
            return exit_node
        
        # Try-catch-finally
        elif node_type == 'try_statement':
            try_entry = cfg.create_node(node, "try_entry")
            
            # Try body
            body = node.child_by_field_name('body')
            try_current = try_entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_typescript_cfg(child, cfg)
                        cfg.add_edge(try_current, next_node)
                        try_current = next_node
            
            merge = cfg.create_node(node, "try_merge")
            cfg.add_edge(try_current, merge)
            
            # Catch clause
            handler = node.child_by_field_name('handler')
            if handler:
                catch_entry = cfg.create_node(handler, "catch_entry")
                cfg.add_edge(try_entry, catch_entry)  # Exception path
                
                catch_body = handler.child_by_field_name('body')
                catch_current = catch_entry
                if catch_body:
                    for child in catch_body.children:
                        if child.type not in {'{', '}', 'comment', '\n', ' '}:
                            next_node = self._build_typescript_cfg(child, cfg)
                            cfg.add_edge(catch_current, next_node)
                            catch_current = next_node
                
                cfg.add_edge(catch_current, merge)
            
            # Finally clause
            finalizer = node.child_by_field_name('finalizer')
            if finalizer:
                finally_entry = cfg.create_node(finalizer, "finally_entry")
                cfg.add_edge(merge, finally_entry)
                
                finally_current = finally_entry
                for child in finalizer.children:
                    if child.type not in {'{', '}', 'finally', 'comment', '\n', ' '}:
                        next_node = self._build_typescript_cfg(child, cfg)
                        cfg.add_edge(finally_current, next_node)
                        finally_current = next_node
                
                return finally_current
            
            return merge
        
        # Switch statement
        elif node_type == 'switch_statement':
            value = node.child_by_field_name('value')
            switch_node = cfg.create_node(value if value else node, "switch_value")
            
            merge = cfg.create_node(node, "switch_merge")
            
            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    if child.type in {'switch_case', 'switch_default'}:
                        case_entry = cfg.create_node(child, "case_entry")
                        cfg.add_edge(switch_node, case_entry)
                        
                        case_current = case_entry
                        for stmt in child.children:
                            if stmt.type not in {'case', 'default', ':', 'comment', '\n', ' '} and not stmt.type.endswith('_expression'):
                                next_node = self._build_typescript_cfg(stmt, cfg)
                                cfg.add_edge(case_current, next_node)
                                case_current = next_node
                        
                        cfg.add_edge(case_current, merge)
            
            return merge
        
        # Default: create a simple node
        else:
            return cfg.create_node(node, node_type)

    def _build_kotlin_cfg(self, node: Node, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for Kotlin tree-sitter AST.

        Args:
            node: tree-sitter Node
            cfg: Control Flow Graph

        Returns:
            Last CFG node created
        """
        node_type = node.type
        
        # Source file entry point
        if node_type == 'source_file':
            entry = cfg.create_node(node, "entry")
            cfg.entry = entry
            
            current = entry
            for child in node.children:
                if child.type not in {'package_header', 'import_list', 'import_header', 'comment', '\n', ' '}:
                    next_node = self._build_kotlin_cfg(child, cfg)
                    cfg.add_edge(current, next_node)
                    current = next_node
            
            exit_node = cfg.create_node(node, "exit")
            cfg.exit = exit_node
            cfg.add_edge(current, exit_node)
            
            return exit_node
        
        # Function declarations
        elif node_type in {'function_declaration', 'anonymous_function', 'lambda_literal'}:
            entry = cfg.create_node(node, "func_entry")
            if not cfg.entry:
                cfg.entry = entry
            
            # Find function body - may be nested in function_body -> block
            body = None
            for child in node.children:
                if child.type == 'function_body':
                    # Look for block inside function_body
                    for subchild in child.children:
                        if subchild.type == 'block':
                            body = subchild
                            break
                    if not body:
                        body = child
                    break
                elif child.type == 'block':
                    body = child
                    break
                elif child.type == 'statements':  # lambda body
                    body = child
                    break
            
            current = entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_kotlin_cfg(child, cfg)
                        cfg.add_edge(current, next_node)
                        current = next_node
            
            exit_node = cfg.create_node(node, "func_exit")
            if not cfg.exit:
                cfg.exit = exit_node
            cfg.add_edge(current, exit_node)
            
            return exit_node
        
        # If expressions
        elif node_type == 'if_expression':
            condition = None
            then_body = None
            else_body = None
            
            for child in node.children:
                if child.type == 'parenthesized_expression':
                    condition = child
                elif child.type == 'control_structure_body' and then_body is None:
                    then_body = child
                elif child.type == 'control_structure_body':
                    else_body = child
            
            cond_node = cfg.create_node(condition if condition else node, "if_cond")
            
            # Then branch
            then_entry = cfg.create_node(node, "then_entry")
            cfg.add_edge(cond_node, then_entry)
            
            then_current = then_entry
            if then_body:
                for child in then_body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_kotlin_cfg(child, cfg)
                        cfg.add_edge(then_current, next_node)
                        then_current = next_node
            
            # Else branch
            if else_body:
                else_entry = cfg.create_node(node, "else_entry")
                cfg.add_edge(cond_node, else_entry)
                
                else_current = else_entry
                for child in else_body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_kotlin_cfg(child, cfg)
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
        
        # While loops
        elif node_type == 'while_statement':
            condition = None
            body = None
            
            for child in node.children:
                if child.type == 'parenthesized_expression':
                    condition = child
                elif child.type == 'control_structure_body':
                    body = child
            
            cond_node = cfg.create_node(condition if condition else node, "while_cond")
            
            body_entry = cfg.create_node(node, "while_body")
            cfg.add_edge(cond_node, body_entry)
            
            body_current = body_entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_kotlin_cfg(child, cfg)
                        cfg.add_edge(body_current, next_node)
                        body_current = next_node
            
            cfg.add_edge(body_current, cond_node)
            
            exit_node = cfg.create_node(node, "while_exit")
            cfg.add_edge(cond_node, exit_node)
            
            return exit_node
        
        # For loops
        elif node_type == 'for_statement':
            iter_node = cfg.create_node(node, "for_iter")
            
            body = None
            for child in node.children:
                if child.type == 'control_structure_body':
                    body = child
                    break
            
            body_entry = cfg.create_node(node, "for_body")
            cfg.add_edge(iter_node, body_entry)
            
            body_current = body_entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_kotlin_cfg(child, cfg)
                        cfg.add_edge(body_current, next_node)
                        body_current = next_node
            
            cfg.add_edge(body_current, iter_node)
            
            exit_node = cfg.create_node(node, "for_exit")
            cfg.add_edge(iter_node, exit_node)
            
            return exit_node
        
        # Try-catch-finally
        elif node_type == 'try_expression':
            try_entry = cfg.create_node(node, "try_entry")
            
            # Try body
            try_body = None
            catch_blocks = []
            finally_block = None
            
            for child in node.children:
                if child.type == 'statements':
                    try_body = child
                elif child.type == 'catch_block':
                    catch_blocks.append(child)
                elif child.type == 'finally_block':
                    finally_block = child
            
            try_current = try_entry
            if try_body:
                for child in try_body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_kotlin_cfg(child, cfg)
                        cfg.add_edge(try_current, next_node)
                        try_current = next_node
            
            merge = cfg.create_node(node, "try_merge")
            cfg.add_edge(try_current, merge)
            
            # Catch blocks
            for catch_block in catch_blocks:
                catch_entry = cfg.create_node(catch_block, "catch_entry")
                cfg.add_edge(try_entry, catch_entry)
                
                catch_body = None
                for child in catch_block.children:
                    if child.type == 'statements':
                        catch_body = child
                        break
                
                catch_current = catch_entry
                if catch_body:
                    for child in catch_body.children:
                        if child.type not in {'{', '}', 'comment', '\n', ' '}:
                            next_node = self._build_kotlin_cfg(child, cfg)
                            cfg.add_edge(catch_current, next_node)
                            catch_current = next_node
                
                cfg.add_edge(catch_current, merge)
            
            # Finally block
            if finally_block:
                finally_entry = cfg.create_node(finally_block, "finally_entry")
                cfg.add_edge(merge, finally_entry)
                
                finally_body = None
                for child in finally_block.children:
                    if child.type == 'statements':
                        finally_body = child
                        break
                
                finally_current = finally_entry
                if finally_body:
                    for child in finally_body.children:
                        if child.type not in {'{', '}', 'comment', '\n', ' '}:
                            next_node = self._build_kotlin_cfg(child, cfg)
                            cfg.add_edge(finally_current, next_node)
                            finally_current = next_node
                
                return finally_current
            
            return merge
        
        # When expression (Kotlin's switch)
        elif node_type == 'when_expression':
            subject = None
            for child in node.children:
                if child.type == 'when_subject':
                    subject = child
                    break
            
            when_node = cfg.create_node(subject if subject else node, "when_subject")
            merge = cfg.create_node(node, "when_merge")
            
            for child in node.children:
                if child.type == 'when_entry':
                    entry_node = cfg.create_node(child, "when_entry")
                    cfg.add_edge(when_node, entry_node)
                    
                    entry_current = entry_node
                    for subchild in child.children:
                        if subchild.type == 'control_structure_body':
                            for stmt in subchild.children:
                                if stmt.type not in {'{', '}', 'comment', '\n', ' '}:
                                    next_node = self._build_kotlin_cfg(stmt, cfg)
                                    cfg.add_edge(entry_current, next_node)
                                    entry_current = next_node
                    
                    cfg.add_edge(entry_current, merge)
            
            return merge
        
        # Default: create a simple node
        else:
            return cfg.create_node(node, node_type)

    def _build_go_cfg(self, tree: Any, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for Go AST.

        Args:
            tree: tree-sitter Tree
            cfg: Control Flow Graph

        Returns:
            Last CFG node created
        """
        root = tree.root_node if hasattr(tree, 'root_node') else tree
        
        entry = cfg.create_node(root, "entry")
        cfg.entry = entry
        
        current = entry
        for child in root.children:
            if child.type not in {'package_clause', 'import_declaration', 'comment', '\n', ' '}:
                next_node = self._build_go_cfg_node(child, cfg)
                cfg.add_edge(current, next_node)
                current = next_node
        
        exit_node = cfg.create_node(root, "exit")
        cfg.add_edge(current, exit_node)
        cfg.exit = exit_node
        
        return exit_node

    def _build_go_cfg_node(self, node: Node, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for a Go AST node.

        Args:
            node: tree-sitter Node
            cfg: Control Flow Graph

        Returns:
            CFG node
        """
        node_type = node.type
        
        # Function declarations
        if node_type in {'function_declaration', 'method_declaration'}:
            func_entry = cfg.create_node(node, "func_entry")
            
            # Find function body
            body = node.child_by_field_name('body')
            if body:
                current = func_entry
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_go_cfg_node(child, cfg)
                        cfg.add_edge(current, next_node)
                        current = next_node
                
                func_exit = cfg.create_node(node, "func_exit")
                cfg.add_edge(current, func_exit)
                return func_exit
            
            return func_entry
        
        # If statements
        elif node_type == 'if_statement':
            condition = node.child_by_field_name('condition')
            consequence = node.child_by_field_name('consequence')
            alternative = node.child_by_field_name('alternative')
            
            cond_node = cfg.create_node(condition if condition else node, "if_cond")
            
            # Then branch
            then_entry = cfg.create_node(node, "then_entry")
            cfg.add_edge(cond_node, then_entry)
            
            then_current = then_entry
            if consequence:
                for child in consequence.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_go_cfg_node(child, cfg)
                        cfg.add_edge(then_current, next_node)
                        then_current = next_node
            
            # Else branch
            if alternative:
                else_entry = cfg.create_node(node, "else_entry")
                cfg.add_edge(cond_node, else_entry)
                
                else_current = else_entry
                # Handle else if
                if alternative.type == 'if_statement':
                    else_node = self._build_go_cfg_node(alternative, cfg)
                    cfg.add_edge(else_current, else_node)
                    else_current = else_node
                else:
                    for child in alternative.children:
                        if child.type not in {'{', '}', 'comment', '\n', ' '}:
                            next_node = self._build_go_cfg_node(child, cfg)
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
        
        # For loops (Go only has for loops)
        elif node_type == 'for_statement':
            init = node.child_by_field_name('initializer')
            cond = node.child_by_field_name('condition')
            update = node.child_by_field_name('update')
            body = node.child_by_field_name('body')
            
            # Init
            if init:
                init_node = cfg.create_node(init, "for_init")
            else:
                init_node = cfg.create_node(node, "for_entry")
            
            # Condition
            cond_node = cfg.create_node(cond if cond else node, "for_cond")
            cfg.add_edge(init_node, cond_node)
            
            # Body
            body_entry = cfg.create_node(node, "for_body")
            cfg.add_edge(cond_node, body_entry)
            
            body_current = body_entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_go_cfg_node(child, cfg)
                        cfg.add_edge(body_current, next_node)
                        body_current = next_node
            
            # Update
            if update:
                update_node = cfg.create_node(update, "for_update")
                cfg.add_edge(body_current, update_node)
                cfg.add_edge(update_node, cond_node)
            else:
                cfg.add_edge(body_current, cond_node)
            
            exit_node = cfg.create_node(node, "for_exit")
            cfg.add_edge(cond_node, exit_node)
            
            return exit_node
        
        # Range loops
        elif node_type == 'for_range_statement':
            range_clause = None
            body = node.child_by_field_name('body')
            
            for child in node.children:
                if child.type == 'range_clause':
                    range_clause = child
                    break
            
            iter_node = cfg.create_node(range_clause if range_clause else node, "range_iter")
            
            body_entry = cfg.create_node(node, "range_body")
            cfg.add_edge(iter_node, body_entry)
            
            body_current = body_entry
            if body:
                for child in body.children:
                    if child.type not in {'{', '}', 'comment', '\n', ' '}:
                        next_node = self._build_go_cfg_node(child, cfg)
                        cfg.add_edge(body_current, next_node)
                        body_current = next_node
            
            cfg.add_edge(body_current, iter_node)
            
            exit_node = cfg.create_node(node, "range_exit")
            cfg.add_edge(iter_node, exit_node)
            
            return exit_node
        
        # Switch statements
        elif node_type == 'expression_switch_statement':
            value = node.child_by_field_name('value')
            
            switch_node = cfg.create_node(value if value else node, "switch_value")
            merge = cfg.create_node(node, "switch_merge")
            
            for child in node.children:
                if child.type in {'expression_case', 'default_case'}:
                    case_entry = cfg.create_node(child, "case_entry")
                    cfg.add_edge(switch_node, case_entry)
                    
                    case_current = case_entry
                    for subchild in child.children:
                        if subchild.type not in {'case', 'default', ':', 'expression_list', 'comment', '\n', ' '}:
                            next_node = self._build_go_cfg_node(subchild, cfg)
                            cfg.add_edge(case_current, next_node)
                            case_current = next_node
                    
                    cfg.add_edge(case_current, merge)
            
            return merge
        
        # Select statements (for channels)
        elif node_type == 'select_statement':
            select_node = cfg.create_node(node, "select")
            merge = cfg.create_node(node, "select_merge")
            
            for child in node.children:
                if child.type == 'communication_case':
                    case_entry = cfg.create_node(child, "comm_case")
                    cfg.add_edge(select_node, case_entry)
                    
                    case_current = case_entry
                    for subchild in child.children:
                        if subchild.type not in {'case', 'default', ':', 'comment', '\n', ' '}:
                            next_node = self._build_go_cfg_node(subchild, cfg)
                            cfg.add_edge(case_current, next_node)
                            case_current = next_node
                    
                    cfg.add_edge(case_current, merge)
            
            return merge
        
        # Defer statements
        elif node_type == 'defer_statement':
            return cfg.create_node(node, "defer")
        
        # Go statements (goroutines)
        elif node_type == 'go_statement':
            return cfg.create_node(node, "go")
        
        # Return statements
        elif node_type == 'return_statement':
            return cfg.create_node(node, "return")
        
        # Default: create a simple node
        else:
            return cfg.create_node(node, node_type)

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
