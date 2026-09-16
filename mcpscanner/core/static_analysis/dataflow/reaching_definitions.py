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

"""Reaching definitions analysis with reversed approach for MCP entry points."""

import ast
from dataclasses import dataclass, field

from ..cfg.builder import CFGNode
from ..parser.base import BaseParser
from .python_base import PythonDataFlowAnalyzer


@dataclass(frozen=True)
class Definition:
    """Represents a variable definition."""

    var: str
    node_id: int
    is_parameter: bool = False  # Track if this is an MCP entry point parameter

    def __hash__(self) -> int:
        """Hash for set membership."""
        return hash((self.var, self.node_id, self.is_parameter))


@dataclass
class ReachingDefsFact:
    """Reaching definitions dataflow fact."""

    defs: set[Definition] = field(default_factory=set)

    def copy(self) -> "ReachingDefsFact":
        """Create a copy."""
        return ReachingDefsFact(defs=self.defs.copy())

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, ReachingDefsFact):
            return False
        return self.defs == other.defs


class ReachingDefinitionsAnalysis(PythonDataFlowAnalyzer[ReachingDefsFact]):
    """Analyzes which definitions reach which program points.

    REVERSED APPROACH: Tracks how MCP entry point parameters flow through definitions.
    """

    def __init__(self, analyzer: BaseParser, parameter_names: list[str] = None):
        """Initialize reaching definitions analyzer.

        Args:
            analyzer: Language-specific analyzer
            parameter_names: MCP entry point parameter names (for reversed approach)
        """
        super().__init__(analyzer)
        self.parameter_names = parameter_names or []
        self.use_def_chains: dict[tuple[int, str], list[Definition]] = {}

    def analyze_reaching_defs(self) -> dict[tuple[int, str], list[Definition]]:
        """Run reaching definitions analysis.

        Returns:
            Use-def chains: (node_id, var) -> list of reaching definitions
        """
        self._ensure_cfg()

        # Initialize with parameter definitions (REVERSED APPROACH)
        initial_fact = ReachingDefsFact()
        for param_name in self.parameter_names:
            # Parameters are initial definitions (sources)
            param_def = Definition(var=param_name, node_id=-1, is_parameter=True)
            initial_fact.defs.add(param_def)

        self.analyze(initial_fact)
        self._compute_use_def_chains()

        return self.use_def_chains

    def _transfer_python(self, cfg_node: CFGNode, fact: ReachingDefsFact) -> None:
        """Apply one node's definitions to the reaching set.

        Args:
            cfg_node: CFG node, whose id labels the definitions it generates
            fact: Reaching definitions fact to update
        """
        ast_node = cfg_node.ast_node

        if isinstance(ast_node, ast.Assign):
            for target in ast_node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id

                    # GEN: Check if RHS uses any parameters BEFORE kill
                    # This preserves taint chain for self-referential updates (x = x + 1)
                    uses_param = self._expr_uses_parameters(ast_node.value, fact)

                    # KILL: Remove all previous definitions of this variable
                    fact.defs = {d for d in fact.defs if d.var != var_name}

                    # Add new definition with preserved parameter flag
                    new_def = Definition(
                        var=var_name, node_id=cfg_node.id, is_parameter=uses_param
                    )
                    fact.defs.add(new_def)

        elif isinstance(ast_node, ast.AugAssign):
            if isinstance(ast_node.target, ast.Name):
                var_name = ast_node.target.id

                # Check BEFORE kill (augmented assignments always reference the target)
                uses_param = self._expr_uses_parameters(ast_node.value, fact)
                # Also check if target itself is parameter-derived
                target_defs = [d for d in fact.defs if d.var == var_name]
                if any(d.is_parameter for d in target_defs):
                    uses_param = True

                fact.defs = {d for d in fact.defs if d.var != var_name}

                new_def = Definition(
                    var=var_name, node_id=cfg_node.id, is_parameter=uses_param
                )
                fact.defs.add(new_def)

        elif isinstance(ast_node, ast.For):
            if isinstance(ast_node.target, ast.Name):
                var_name = ast_node.target.id

                # Check BEFORE kill
                uses_param = self._expr_uses_parameters(ast_node.iter, fact)

                fact.defs = {d for d in fact.defs if d.var != var_name}

                new_def = Definition(
                    var=var_name, node_id=cfg_node.id, is_parameter=uses_param
                )
                fact.defs.add(new_def)

    def _expr_uses_parameters(self, expr: ast.AST, fact: ReachingDefsFact) -> bool:
        """Check if expression uses any MCP entry point parameters (transitively).

        Args:
            expr: Expression node
            fact: Current reaching definitions

        Returns:
            True if expression uses parameters
        """
        for node in ast.walk(expr):
            if isinstance(node, ast.Name):
                # Check if this variable has parameter definitions reaching it
                reaching_defs = [d for d in fact.defs if d.var == node.id]
                if any(d.is_parameter for d in reaching_defs):
                    return True
        return False

    def merge(self, facts: list[ReachingDefsFact]) -> ReachingDefsFact:
        """Merge multiple reaching definitions facts.

        Args:
            facts: List of facts to merge

        Returns:
            Merged fact (union of all definitions)
        """
        if not facts:
            return ReachingDefsFact()

        merged = ReachingDefsFact()
        for fact in facts:
            merged.defs.update(fact.defs)

        return merged

    def _compute_use_def_chains(self) -> None:
        """Compute use-def chains from reaching definitions."""
        if not self.cfg:
            return

        for node in self.cfg.nodes:
            ast_node = node.ast_node

            reaching = self.in_facts.get(node.id, ReachingDefsFact())
            uses = self._used_names(ast_node)

            for var in uses:
                reaching_defs = [d for d in reaching.defs if d.var == var]
                self.use_def_chains[(node.id, var)] = reaching_defs

    def get_reaching_defs(self, node_id: int, var: str) -> list[Definition]:
        """Get reaching definitions for a variable at a node.

        Args:
            node_id: CFG node ID
            var: Variable name

        Returns:
            List of reaching definitions
        """
        return self.use_def_chains.get((node_id, var), [])

    def get_parameter_influenced_vars(self) -> set[str]:
        """Get all variables influenced by MCP entry point parameters.

        Returns:
            Set of variable names that depend on parameters
        """
        influenced = set()

        for (node_id, var), defs in self.use_def_chains.items():
            if any(d.is_parameter for d in defs):
                influenced.add(var)

        return influenced
