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

"""Shared plumbing for the Python-AST dataflow analyses.

Reaching definitions, liveness, available expressions, and forward taint each
carried their own verbatim copy of the two pieces below. Keeping one copy is
not cosmetic: the :meth:`PythonDataFlowAnalyzer._ensure_cfg` guard had to be
patched in four separate files when a module-wide rebuild was found to be
clobbering function-scoped CFGs.
"""

from __future__ import annotations

import ast
from typing import Generic, TypeVar

from ..cfg.builder import CFGNode, DataFlowAnalyzer
from ..parser.python_parser import PythonParser

T = TypeVar("T")


class PythonDataFlowAnalyzer(DataFlowAnalyzer[T], Generic[T]):
    """Base for dataflow analyses that interpret Python AST nodes.

    Subclasses implement :meth:`_transfer_python` to apply one CFG node's
    effect to a fact in place; the copy-dispatch-return wrapper around it is
    shared.
    """

    def _ensure_cfg(self) -> None:
        """Build a module-wide CFG only when none is already installed.

        ``build_cfg_for_function`` narrows the CFG to a single function body.
        Rebuilding unconditionally would silently widen the analysis back to
        the whole module and leak facts between sibling functions.
        """
        if not self.cfg:
            self.build_cfg()

    def transfer(self, node: CFGNode, fact: T) -> T:
        """Copy the incoming fact and let the language pass mutate the copy.

        Direction is irrelevant here — backward analyses receive the
        out-fact and return the in-fact through the same wrapper.
        """
        new_fact = fact.copy()  # type: ignore[attr-defined]
        if isinstance(self.analyzer, PythonParser):
            self._transfer_python(node, new_fact)
        return new_fact

    def _transfer_python(self, node: CFGNode, fact: T) -> None:
        """Apply ``node``'s effect to ``fact`` in place.

        Implementations read the AST via ``node.ast_node``; those needing the
        CFG node identity (reaching definitions) use ``node.id``.
        """
        raise NotImplementedError

    @staticmethod
    def _used_names(node: ast.AST) -> set[str]:
        """Return every variable read within ``node``."""
        return {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
        }
