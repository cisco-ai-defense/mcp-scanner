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

"""Unified CFG builder that works with language-agnostic AST."""

from typing import Optional

from ..unified_ast import NodeType, UnifiedASTNode
from .builder import CFGNode, ControlFlowGraph


class UnifiedCFGBuilder:
    """Builds Control Flow Graphs from Unified AST (language-agnostic)."""
    
    def build_cfg(self, unified_ast: UnifiedASTNode) -> ControlFlowGraph:
        """Build CFG from unified AST.
        
        Args:
            unified_ast: Unified AST node (typically a MODULE or FUNCTION)
            
        Returns:
            Control Flow Graph
        """
        cfg = ControlFlowGraph()
        
        if unified_ast.type == NodeType.MODULE:
            self._build_module_cfg(unified_ast, cfg)
        elif unified_ast.type in [NodeType.FUNCTION, NodeType.ASYNC_FUNCTION]:
            self._build_function_cfg(unified_ast, cfg)
        else:
            # Generic fallback
            entry = cfg.create_node(unified_ast, "entry")
            cfg.entry = entry
            cfg.exit = entry
        
        return cfg
    
    def _build_module_cfg(self, node: UnifiedASTNode, cfg: ControlFlowGraph) -> None:
        """Build CFG for a module.
        
        Args:
            node: Module node
            cfg: Control Flow Graph to populate
        """
        entry = cfg.create_node(node, "entry")
        cfg.entry = entry
        
        current = entry
        for child in node.children:
            next_node = self._build_statement_cfg(child, cfg)
            if next_node:
                cfg.add_edge(current, next_node)
                current = next_node
        
        exit_node = cfg.create_node(node, "exit")
        cfg.exit = exit_node
        cfg.add_edge(current, exit_node)
    
    def _build_function_cfg(self, node: UnifiedASTNode, cfg: ControlFlowGraph) -> None:
        """Build CFG for a function.
        
        Args:
            node: Function node
            cfg: Control Flow Graph to populate
        """
        entry = cfg.create_node(node, "func_entry")
        cfg.entry = entry
        
        current = entry
        for child in node.children:
            next_node = self._build_statement_cfg(child, cfg)
            if next_node:
                cfg.add_edge(current, next_node)
                current = next_node
        
        exit_node = cfg.create_node(node, "func_exit")
        cfg.exit = exit_node
        cfg.add_edge(current, exit_node)
    
    def _build_statement_cfg(self, node: UnifiedASTNode, cfg: ControlFlowGraph) -> Optional[CFGNode]:
        """Build CFG for a statement.
        
        Args:
            node: Statement node
            cfg: Control Flow Graph
            
        Returns:
            Last CFG node created, or None
        """
        if node.type == NodeType.IF:
            return self._build_if_cfg(node, cfg)
        elif node.type == NodeType.WHILE:
            return self._build_while_cfg(node, cfg)
        elif node.type == NodeType.FOR:
            return self._build_for_cfg(node, cfg)
        elif node.type == NodeType.TRY:
            return self._build_try_cfg(node, cfg)
        elif node.type == NodeType.RETURN:
            return self._build_return_cfg(node, cfg)
        elif node.type in [NodeType.ASSIGNMENT, NodeType.CALL]:
            # Simple statement
            return cfg.create_node(node, node.type.value)
        elif node.type in [NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.CLASS]:
            # Nested function/class - create a node but don't recurse
            return cfg.create_node(node, node.type.value)
        else:
            # Generic statement
            return cfg.create_node(node, node.type.value)
    
    def _build_if_cfg(self, node: UnifiedASTNode, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for an if statement.
        
        Args:
            node: If statement node
            cfg: Control Flow Graph
            
        Returns:
            Merge node after if/else
        """
        # Create condition node
        cond_node = cfg.create_node(node, "if_cond")
        
        # Build then branch
        then_nodes = []
        else_nodes = []
        
        # Separate condition, then, and else children
        # First child is typically the condition
        children = node.children
        if len(children) > 0:
            # Condition is first
            condition = children[0]
            
            # Then branch
            then_start = None
            then_current = None
            for i in range(1, len(children)):
                child = children[i]
                # Check if this is an else branch (another IF or statements after first block)
                if child.type == NodeType.IF and i > 1:
                    # This is an else-if
                    else_nodes.append(child)
                    break
                else:
                    stmt_node = self._build_statement_cfg(child, cfg)
                    if stmt_node:
                        if then_start is None:
                            then_start = stmt_node
                            cfg.add_edge(cond_node, then_start)
                        if then_current:
                            cfg.add_edge(then_current, stmt_node)
                        then_current = stmt_node
                        then_nodes.append(stmt_node)
            
            # If no then branch, create empty node
            if then_start is None:
                then_start = cfg.create_node(node, "then_empty")
                cfg.add_edge(cond_node, then_start)
                then_current = then_start
            
            # Build else branch if exists
            else_start = None
            else_current = None
            if len(else_nodes) > 0:
                for else_child in else_nodes:
                    stmt_node = self._build_statement_cfg(else_child, cfg)
                    if stmt_node:
                        if else_start is None:
                            else_start = stmt_node
                            cfg.add_edge(cond_node, else_start)
                        if else_current:
                            cfg.add_edge(else_current, stmt_node)
                        else_current = stmt_node
        
        # Create merge node
        merge_node = cfg.create_node(node, "if_merge")
        
        # Connect branches to merge
        if then_nodes:
            cfg.add_edge(then_nodes[-1], merge_node)
        else:
            cfg.add_edge(cond_node, merge_node)
        
        if else_nodes:
            # Build else branch
            else_node = self._build_statement_cfg(else_nodes[0], cfg)
            if else_node:
                cfg.add_edge(cond_node, else_node)
                cfg.add_edge(else_node, merge_node)
        else:
            # No else - condition can go directly to merge
            cfg.add_edge(cond_node, merge_node)
        
        return merge_node
    
    def _build_while_cfg(self, node: UnifiedASTNode, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for a while loop.
        
        Args:
            node: While loop node
            cfg: Control Flow Graph
            
        Returns:
            Exit node after loop
        """
        # Create condition node
        cond_node = cfg.create_node(node, "while_cond")
        
        # Build body
        body_start = None
        body_current = None
        for child in node.children[1:]:  # Skip condition
            stmt_node = self._build_statement_cfg(child, cfg)
            if stmt_node:
                if body_start is None:
                    body_start = stmt_node
                    cfg.add_edge(cond_node, body_start)
                if body_current:
                    cfg.add_edge(body_current, stmt_node)
                body_current = stmt_node
        
        # Loop back to condition
        if body_current:
            cfg.add_edge(body_current, cond_node)
        
        # Create exit node
        exit_node = cfg.create_node(node, "while_exit")
        cfg.add_edge(cond_node, exit_node)
        
        return exit_node
    
    def _build_for_cfg(self, node: UnifiedASTNode, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for a for loop.
        
        Args:
            node: For loop node
            cfg: Control Flow Graph
            
        Returns:
            Exit node after loop
        """
        # Create init/condition node
        init_node = cfg.create_node(node, "for_init")
        
        # Build body
        body_start = None
        body_current = None
        
        # Skip init/condition children, process body
        for child in node.children:
            if child.type not in [NodeType.IDENTIFIER, NodeType.LITERAL, NodeType.ASSIGNMENT]:
                stmt_node = self._build_statement_cfg(child, cfg)
                if stmt_node:
                    if body_start is None:
                        body_start = stmt_node
                        cfg.add_edge(init_node, body_start)
                    if body_current:
                        cfg.add_edge(body_current, stmt_node)
                    body_current = stmt_node
        
        # Loop back to init
        if body_current:
            cfg.add_edge(body_current, init_node)
        
        # Create exit node
        exit_node = cfg.create_node(node, "for_exit")
        cfg.add_edge(init_node, exit_node)
        
        return exit_node
    
    def _build_try_cfg(self, node: UnifiedASTNode, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for a try statement.
        
        Args:
            node: Try statement node
            cfg: Control Flow Graph
            
        Returns:
            Merge node after try/catch/finally
        """
        # Create try entry
        try_entry = cfg.create_node(node, "try_entry")
        
        # Build try body
        try_current = try_entry
        except_nodes = []
        finally_nodes = []
        
        for child in node.children:
            if child.type == NodeType.EXCEPT:
                except_nodes.append(child)
            elif child.type == NodeType.FINALLY:
                finally_nodes.append(child)
            else:
                stmt_node = self._build_statement_cfg(child, cfg)
                if stmt_node:
                    cfg.add_edge(try_current, stmt_node)
                    try_current = stmt_node
        
        # Build except handlers
        except_current = None
        for except_node in except_nodes:
            except_entry = cfg.create_node(except_node, "except_entry")
            cfg.add_edge(try_entry, except_entry)  # Exception can occur at any point
            
            except_current = except_entry
            for child in except_node.children:
                stmt_node = self._build_statement_cfg(child, cfg)
                if stmt_node:
                    cfg.add_edge(except_current, stmt_node)
                    except_current = stmt_node
        
        # Build finally
        finally_current = None
        if finally_nodes:
            finally_entry = cfg.create_node(finally_nodes[0], "finally_entry")
            cfg.add_edge(try_current, finally_entry)
            if except_current:
                cfg.add_edge(except_current, finally_entry)
            
            finally_current = finally_entry
            for child in finally_nodes[0].children:
                stmt_node = self._build_statement_cfg(child, cfg)
                if stmt_node:
                    cfg.add_edge(finally_current, stmt_node)
                    finally_current = stmt_node
        
        # Create merge node
        merge_node = cfg.create_node(node, "try_merge")
        
        if finally_current:
            cfg.add_edge(finally_current, merge_node)
        else:
            cfg.add_edge(try_current, merge_node)
            if except_current:
                cfg.add_edge(except_current, merge_node)
        
        return merge_node
    
    def _build_return_cfg(self, node: UnifiedASTNode, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for a return statement.
        
        Args:
            node: Return statement node
            cfg: Control Flow Graph
            
        Returns:
            Return node
        """
        return_node = cfg.create_node(node, "return")
        
        # Return nodes typically connect to function exit
        # This will be handled by the caller
        
        return return_node
