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

"""Language-agnostic CFG builder for tree-sitter ASTs.

This module provides Control Flow Graph construction that works with
any tree-sitter parsed language, enabling full dataflow analysis
across TypeScript, JavaScript, Go, Java, Kotlin, C#, Ruby, Rust, and PHP.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from tree_sitter import Node


@dataclass
class TSCFGNode:
    """Control Flow Graph node for tree-sitter AST."""
    
    node_id: int
    ast_node: Node
    node_type: str
    label: str = ""
    predecessors: List["TSCFGNode"] = field(default_factory=list)
    successors: List["TSCFGNode"] = field(default_factory=list)
    
    def __repr__(self) -> str:
        return f"TSCFGNode({self.node_id}, {self.node_type}, {self.label[:30]})"


class TreeSitterCFG:
    """Control Flow Graph for tree-sitter AST."""
    
    def __init__(self):
        self.nodes: List[TSCFGNode] = []
        self.entry: Optional[TSCFGNode] = None
        self.exit: Optional[TSCFGNode] = None
        self._node_counter = 0
    
    def create_node(self, ast_node: Node, label: str = "") -> TSCFGNode:
        """Create a new CFG node."""
        node = TSCFGNode(
            node_id=self._node_counter,
            ast_node=ast_node,
            node_type=ast_node.type,
            label=label or ast_node.type,
        )
        self._node_counter += 1
        self.nodes.append(node)
        return node
    
    def add_edge(self, from_node: TSCFGNode, to_node: TSCFGNode) -> None:
        """Add an edge between two nodes."""
        if to_node not in from_node.successors:
            from_node.successors.append(to_node)
        if from_node not in to_node.predecessors:
            to_node.predecessors.append(from_node)


class TreeSitterCFGBuilder:
    """Builds Control Flow Graphs from tree-sitter ASTs.
    
    Language-agnostic CFG construction that handles common control flow
    patterns across all supported languages.
    """
    
    # Statement node types per language
    STATEMENT_TYPES: Dict[str, Set[str]] = {
        "javascript": {
            "expression_statement", "variable_declaration", "lexical_declaration",
            "return_statement", "if_statement", "for_statement", "for_in_statement",
            "while_statement", "do_statement", "switch_statement", "try_statement",
            "throw_statement", "break_statement", "continue_statement",
        },
        "typescript": {
            "expression_statement", "variable_declaration", "lexical_declaration",
            "return_statement", "if_statement", "for_statement", "for_in_statement",
            "while_statement", "do_statement", "switch_statement", "try_statement",
            "throw_statement", "break_statement", "continue_statement",
        },
        "go": {
            "expression_statement", "short_var_declaration", "var_declaration",
            "return_statement", "if_statement", "for_statement", "switch_statement",
            "select_statement", "go_statement", "defer_statement",
        },
        "java": {
            "expression_statement", "local_variable_declaration",
            "return_statement", "if_statement", "for_statement", "enhanced_for_statement",
            "while_statement", "do_statement", "switch_expression", "try_statement",
            "throw_statement", "break_statement", "continue_statement",
        },
        "kotlin": {
            "expression", "property_declaration", "variable_declaration",
            "return_expression", "if_expression", "for_statement", "while_statement",
            "do_while_statement", "when_expression", "try_expression",
            "throw_expression", "break_expression", "continue_expression",
        },
        "c_sharp": {
            "expression_statement", "local_declaration_statement",
            "return_statement", "if_statement", "for_statement", "foreach_statement",
            "while_statement", "do_statement", "switch_statement", "try_statement",
            "throw_statement", "break_statement", "continue_statement",
        },
        "ruby": {
            "expression", "assignment", "return", "if", "unless", "case",
            "for", "while", "until", "begin", "rescue", "raise",
        },
        "rust": {
            "expression_statement", "let_declaration",
            "return_expression", "if_expression", "for_expression", "while_expression",
            "loop_expression", "match_expression", "break_expression", "continue_expression",
        },
        "php": {
            "expression_statement", "echo_statement", "return_statement",
            "if_statement", "for_statement", "foreach_statement", "while_statement",
            "do_statement", "switch_statement", "try_statement", "throw_expression",
        },
    }
    
    # Branch node types (nodes that create control flow branches)
    BRANCH_TYPES = {
        "if_statement", "if_expression", "if",
        "for_statement", "for_expression", "for", "for_in_statement", 
        "enhanced_for_statement", "foreach_statement",
        "while_statement", "while_expression", "while", "until",
        "do_statement", "do_while_statement",
        "switch_statement", "switch_expression", "when_expression", "match_expression", "case",
        "try_statement", "try_expression", "begin",
        "ternary_expression", "conditional_expression",
    }
    
    # Return/exit node types
    EXIT_TYPES = {
        "return_statement", "return_expression", "return",
        "throw_statement", "throw_expression", "raise",
        "break_statement", "break_expression", "break",
        "continue_statement", "continue_expression", "continue",
    }
    
    def __init__(self, language: str):
        """Initialize CFG builder for a specific language."""
        self.language = language
        self.cfg = TreeSitterCFG()
        self.statement_types = self.STATEMENT_TYPES.get(language, set())
    
    def build(self, function_node: Node) -> TreeSitterCFG:
        """Build CFG from a function AST node."""
        self.cfg = TreeSitterCFG()
        
        # Create entry node
        self.cfg.entry = self.cfg.create_node(function_node, "ENTRY")
        
        # Create exit node (placeholder)
        exit_node = self.cfg.create_node(function_node, "EXIT")
        self.cfg.exit = exit_node
        
        # Get function body
        body = self._get_function_body(function_node)
        if body:
            # Build CFG for the body
            first_node, last_nodes = self._build_block(body)
            
            if first_node:
                self.cfg.add_edge(self.cfg.entry, first_node)
                
                # Connect all exit points to the exit node
                for last_node in last_nodes:
                    self.cfg.add_edge(last_node, self.cfg.exit)
            else:
                # Empty function
                self.cfg.add_edge(self.cfg.entry, self.cfg.exit)
        else:
            self.cfg.add_edge(self.cfg.entry, self.cfg.exit)
        
        return self.cfg
    
    def _get_function_body(self, node: Node) -> Optional[Node]:
        """Get the body of a function node."""
        # Try common field names
        body = node.child_by_field_name("body")
        if body:
            return body
        
        # Try to find block/statement_block child
        for child in node.children:
            if child.type in ("block", "statement_block", "compound_statement", 
                             "function_body", "method_body"):
                return child
        
        return None
    
    def _build_block(self, block_node: Node) -> tuple[Optional[TSCFGNode], List[TSCFGNode]]:
        """Build CFG for a block of statements.
        
        Returns:
            Tuple of (first_node, list_of_exit_nodes)
        """
        statements = self._get_statements(block_node)
        
        if not statements:
            return None, []
        
        first_node = None
        current_exits: List[TSCFGNode] = []
        
        for stmt in statements:
            stmt_first, stmt_exits = self._build_statement(stmt)
            
            if stmt_first is None:
                continue
            
            if first_node is None:
                first_node = stmt_first
            
            # Connect previous exits to this statement
            for exit_node in current_exits:
                self.cfg.add_edge(exit_node, stmt_first)
            
            current_exits = stmt_exits
        
        return first_node, current_exits
    
    def _get_statements(self, block_node: Node) -> List[Node]:
        """Get statement children from a block node."""
        statements = []
        
        for child in block_node.children:
            # Skip punctuation and keywords
            if child.type in ("{", "}", "(", ")", ";", ","):
                continue
            
            # Include statements and expressions
            if child.type in self.statement_types or child.is_named:
                statements.append(child)
        
        return statements
    
    def _build_statement(self, stmt: Node) -> tuple[Optional[TSCFGNode], List[TSCFGNode]]:
        """Build CFG for a single statement.
        
        Returns:
            Tuple of (first_node, list_of_exit_nodes)
        """
        stmt_type = stmt.type
        
        # Handle control flow statements
        if stmt_type in ("if_statement", "if_expression", "if"):
            return self._build_if(stmt)
        elif stmt_type in ("for_statement", "for_expression", "for", "for_in_statement",
                          "enhanced_for_statement", "foreach_statement"):
            return self._build_for(stmt)
        elif stmt_type in ("while_statement", "while_expression", "while", "until"):
            return self._build_while(stmt)
        elif stmt_type in ("do_statement", "do_while_statement"):
            return self._build_do_while(stmt)
        elif stmt_type in ("try_statement", "try_expression", "begin"):
            return self._build_try(stmt)
        elif stmt_type in ("switch_statement", "switch_expression", "when_expression", 
                          "match_expression", "case"):
            return self._build_switch(stmt)
        elif stmt_type in self.EXIT_TYPES:
            return self._build_exit(stmt)
        else:
            # Simple statement - create single node
            node = self.cfg.create_node(stmt)
            return node, [node]
    
    def _build_if(self, stmt: Node) -> tuple[TSCFGNode, List[TSCFGNode]]:
        """Build CFG for if statement."""
        condition_node = self.cfg.create_node(stmt, f"if_condition")
        exits = []
        
        # Get consequence (then branch)
        consequence = stmt.child_by_field_name("consequence") or stmt.child_by_field_name("body")
        if consequence:
            then_first, then_exits = self._build_block(consequence)
            if then_first:
                self.cfg.add_edge(condition_node, then_first)
                exits.extend(then_exits)
            else:
                exits.append(condition_node)
        else:
            exits.append(condition_node)
        
        # Get alternative (else branch)
        alternative = stmt.child_by_field_name("alternative") or stmt.child_by_field_name("else")
        if alternative:
            else_first, else_exits = self._build_block(alternative)
            if else_first:
                self.cfg.add_edge(condition_node, else_first)
                exits.extend(else_exits)
            else:
                exits.append(condition_node)
        else:
            # No else branch - condition can fall through
            exits.append(condition_node)
        
        return condition_node, exits
    
    def _build_for(self, stmt: Node) -> tuple[TSCFGNode, List[TSCFGNode]]:
        """Build CFG for for loop."""
        loop_node = self.cfg.create_node(stmt, "for_loop")
        
        # Get loop body
        body = stmt.child_by_field_name("body")
        if body:
            body_first, body_exits = self._build_block(body)
            if body_first:
                self.cfg.add_edge(loop_node, body_first)
                # Loop back
                for exit_node in body_exits:
                    self.cfg.add_edge(exit_node, loop_node)
        
        # Loop can also exit
        return loop_node, [loop_node]
    
    def _build_while(self, stmt: Node) -> tuple[TSCFGNode, List[TSCFGNode]]:
        """Build CFG for while loop."""
        condition_node = self.cfg.create_node(stmt, "while_condition")
        
        # Get loop body
        body = stmt.child_by_field_name("body")
        if body:
            body_first, body_exits = self._build_block(body)
            if body_first:
                self.cfg.add_edge(condition_node, body_first)
                # Loop back
                for exit_node in body_exits:
                    self.cfg.add_edge(exit_node, condition_node)
        
        return condition_node, [condition_node]
    
    def _build_do_while(self, stmt: Node) -> tuple[TSCFGNode, List[TSCFGNode]]:
        """Build CFG for do-while loop."""
        body = stmt.child_by_field_name("body")
        
        if body:
            body_first, body_exits = self._build_block(body)
            condition_node = self.cfg.create_node(stmt, "do_while_condition")
            
            if body_first:
                # Connect body exits to condition
                for exit_node in body_exits:
                    self.cfg.add_edge(exit_node, condition_node)
                # Loop back
                self.cfg.add_edge(condition_node, body_first)
                return body_first, [condition_node]
        
        # Fallback
        node = self.cfg.create_node(stmt, "do_while")
        return node, [node]
    
    def _build_try(self, stmt: Node) -> tuple[TSCFGNode, List[TSCFGNode]]:
        """Build CFG for try statement."""
        try_node = self.cfg.create_node(stmt, "try")
        exits = []
        
        # Get try body
        body = stmt.child_by_field_name("body")
        if body:
            body_first, body_exits = self._build_block(body)
            if body_first:
                self.cfg.add_edge(try_node, body_first)
                exits.extend(body_exits)
        
        # Get catch/except handlers
        for child in stmt.children:
            if child.type in ("catch_clause", "except_clause", "rescue", "handler"):
                catch_first, catch_exits = self._build_block(child)
                if catch_first:
                    self.cfg.add_edge(try_node, catch_first)
                    exits.extend(catch_exits)
        
        # Get finally block
        finally_block = stmt.child_by_field_name("finalizer") or stmt.child_by_field_name("ensure")
        if finally_block:
            finally_first, finally_exits = self._build_block(finally_block)
            if finally_first:
                # All exits go through finally
                for exit_node in exits:
                    self.cfg.add_edge(exit_node, finally_first)
                exits = finally_exits
        
        if not exits:
            exits = [try_node]
        
        return try_node, exits
    
    def _build_switch(self, stmt: Node) -> tuple[TSCFGNode, List[TSCFGNode]]:
        """Build CFG for switch/match statement."""
        switch_node = self.cfg.create_node(stmt, "switch")
        exits = []
        
        # Get all cases
        for child in stmt.children:
            if child.type in ("switch_case", "switch_default", "case_clause", 
                             "when_entry", "match_arm", "when"):
                case_first, case_exits = self._build_block(child)
                if case_first:
                    self.cfg.add_edge(switch_node, case_first)
                    exits.extend(case_exits)
        
        if not exits:
            exits = [switch_node]
        
        return switch_node, exits
    
    def _build_exit(self, stmt: Node) -> tuple[TSCFGNode, List[TSCFGNode]]:
        """Build CFG for exit statement (return, throw, break, continue)."""
        node = self.cfg.create_node(stmt, stmt.type)
        # Exit statements don't have normal successors
        return node, []
