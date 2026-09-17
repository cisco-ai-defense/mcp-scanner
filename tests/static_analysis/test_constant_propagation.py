# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Tests for constant propagation.

This decides whether a literal that was assembled from pieces can still
be recognised, which is how a pattern match survives a payload being
split across variables. The cases that matter are the ones where a value
should resolve but might not, and the arithmetic that must not raise on
hostile input.
"""

import ast

import pytest

from mcpscanner.core.static_analysis.dataflow.constant_propagation import (
    ConstantPropagationAnalysis,
    SymbolicValue,
    ValueKind,
)
from mcpscanner.core.static_analysis.parser.python_parser import PythonParser


def analyse(source: str) -> ConstantPropagationAnalysis:
    """Run propagation over a snippet and hand back the finished analysis."""
    prop = ConstantPropagationAnalysis(PythonParser("snippet.py", source))
    prop.analyze()
    return prop


def expr(source: str) -> ast.AST:
    """The AST node for a single expression."""
    return ast.parse(source, mode="eval").body


class TestSymbolicValue:
    def test_literal_reports_as_constant(self):
        v = SymbolicValue(kind=ValueKind.LITERAL, value=7)
        assert v.is_constant() is True
        assert v.is_symbolic() is False
        assert repr(v) == "Lit(7)"

    def test_symbolic_reports_as_symbolic(self):
        v = SymbolicValue(kind=ValueKind.SYMBOLIC, expr=expr("a + b"))
        assert v.is_constant() is False
        assert v.is_symbolic() is True
        assert repr(v) == "Sym(a + b)"

    def test_symbolic_without_a_usable_expr_still_reprs(self):
        """repr is used in debug output and must not raise."""
        assert repr(SymbolicValue(kind=ValueKind.SYMBOLIC, expr=None)) == "Sym(?)"

    def test_not_const_repr(self):
        assert repr(SymbolicValue(kind=ValueKind.NOT_CONST)) == "NotCst"


class TestLiteralAssignment:
    @pytest.mark.parametrize(
        "source,name,value",
        [
            ("x = 5", "x", 5),
            ("s = 'payload'", "s", "payload"),
            ("f = 1.5", "f", 1.5),
            ("b = True", "b", True),
            ("n = None", "n", None),
        ],
    )
    def test_literals_are_recorded(self, source, name, value):
        assert analyse(source).get_constant_value(name) == value

    def test_later_assignment_wins(self):
        assert analyse("x = 1\nx = 2").get_constant_value("x") == 2

    def test_unknown_variable_has_no_value(self):
        assert analyse("x = 1").get_constant_value("nope") is None


class TestCopyPropagation:
    def test_value_follows_through_an_alias(self):
        assert analyse("a = 'rm -rf /'\nb = a").get_constant_value("b") == "rm -rf /"

    def test_value_follows_through_a_chain(self):
        prop = analyse("a = 42\nb = a\nc = b\nd = c")
        assert prop.get_constant_value("d") == 42

    def test_assignment_from_an_unknown_name_is_symbolic(self):
        prop = analyse("b = mystery")
        assert prop.get_constant_value("b") is None
        assert prop.symbolic_values["b"].is_symbolic()
        assert prop.symbolic_values["b"].dependencies == {"mystery"}


class TestFoldedArithmetic:
    @pytest.mark.parametrize(
        "source,expected",
        [
            ("x = 2 + 3", 5),
            ("x = 10 - 4", 6),
            ("x = 6 * 7", 42),
            ("x = 9 / 2", 4.5),
            ("x = 9 // 2", 4),
            ("x = 9 % 4", 1),
        ],
    )
    def test_arithmetic_on_literals_is_folded(self, source, expected):
        assert analyse(source).get_constant_value("x") == expected

    def test_split_string_is_reassembled(self):
        """The reason this analysis exists: a payload hidden in halves."""
        prop = analyse("a = 'rm -'\nb = 'rf /'\ncmd = a + b")
        assert prop.get_constant_value("cmd") == "rm -rf /"

    def test_folding_walks_a_chain_of_additions(self):
        prop = analyse("a = 'c'\nb = a + 'u'\nc = b + 'rl'")
        assert prop.get_constant_value("c") == "curl"

    @pytest.mark.parametrize("source", ["x = 1 / 0", "x = 1 // 0", "x = 1 % 0"])
    def test_division_by_zero_yields_no_constant_instead_of_raising(self, source):
        prop = analyse(source)
        assert prop.get_constant_value("x") is None
        assert prop.symbolic_values["x"].is_symbolic()

    def test_type_mismatch_yields_no_constant(self):
        assert analyse("x = 'a' - 1").get_constant_value("x") is None

    def test_unsupported_operator_is_not_folded(self):
        """Only the six arithmetic ops are folded; others stay symbolic."""
        assert analyse("x = 2 ** 3").get_constant_value("x") is None

    def test_partially_known_operands_stay_symbolic_with_dependencies(self):
        prop = analyse("a = 1\nx = a + unknown")
        assert prop.get_constant_value("x") is None
        assert "unknown" in prop.symbolic_values["x"].dependencies


class TestNonConstantSources:
    @pytest.mark.parametrize(
        "source", ["x = foo()", "x = [1, 2]", "x = {'k': 'v'}", "x = lambda: 1"]
    )
    def test_calls_and_containers_are_not_constants(self, source):
        prop = analyse(source)
        assert prop.get_constant_value("x") is None
        assert prop.symbolic_values["x"].kind is ValueKind.NOT_CONST

    def test_tuple_targets_are_skipped(self):
        """Only plain Name targets are tracked."""
        prop = analyse("a, b = 1, 2")
        assert prop.get_constant_value("a") is None

    def test_attribute_target_is_skipped(self):
        prop = analyse("obj.field = 3")
        assert prop.constants == {}


class TestResolveToConstant:
    def test_name_resolves_through_the_table(self):
        prop = analyse("x = 'shell'")
        assert prop.resolve_to_constant(expr("x")) == "shell"

    def test_literal_node_resolves_to_itself(self):
        assert analyse("").resolve_to_constant(expr("'direct'")) == "direct"

    def test_unknown_name_resolves_to_nothing(self):
        assert analyse("").resolve_to_constant(expr("ghost")) is None

    def test_other_node_kinds_resolve_to_nothing(self):
        assert analyse("").resolve_to_constant(expr("foo()")) is None


class TestCanMatchConstant:
    def test_matching_literal(self):
        assert analyse("").can_match_constant("x", expr("'x'")) is True

    def test_non_matching_literal(self):
        assert analyse("").can_match_constant("x", expr("'y'")) is False

    def test_match_through_a_variable(self):
        prop = analyse("cmd = '/bin/sh'")
        assert prop.can_match_constant("/bin/sh", expr("cmd")) is True

    def test_match_against_arithmetic_computed_on_the_fly(self):
        """A BinOp not seen during analysis is still evaluated on demand."""
        prop = analyse("a = 2\nb = 3")
        assert prop.can_match_constant(5, expr("a + b")) is True

    def test_arithmetic_that_does_not_match(self):
        prop = analyse("a = 2\nb = 3")
        assert prop.can_match_constant(99, expr("a + b")) is False

    def test_arithmetic_over_unknown_names_does_not_match(self):
        assert analyse("").can_match_constant(5, expr("p + q")) is False

    def test_unresolvable_node_does_not_match(self):
        assert analyse("").can_match_constant("anything", expr("foo()")) is False

    def test_falsy_constant_is_still_compared(self):
        """resolve_to_constant returning 0 or '' must not read as 'unknown'."""
        prop = analyse("zero = 0")
        # Documents current behaviour: falsy resolutions fall through the
        # `is not None` guard and are compared normally.
        assert prop.can_match_constant(0, expr("zero")) is True


class TestAnalysisLifecycle:
    def test_empty_source_produces_an_empty_table(self):
        prop = analyse("")
        assert prop.constants == {}
        assert prop.symbolic_values == {}

    def test_tables_are_empty_before_analyze_is_called(self):
        prop = ConstantPropagationAnalysis(PythonParser("s.py", "x = 1"))
        assert prop.constants == {}
        prop.analyze()
        assert prop.constants == {"x": 1}

    def test_assignments_inside_functions_are_collected(self):
        """The walk is over the whole tree, not just module level."""
        prop = analyse("def f():\n    inner = 'secret'\n")
        assert prop.get_constant_value("inner") == "secret"

    def test_completion_is_logged_with_table_sizes(self, caplog):
        import logging

        from mcpscanner.core.static_analysis.dataflow import constant_propagation

        logger = constant_propagation.logger
        previous = logger.propagate
        logger.propagate = True
        try:
            with caplog.at_level(logging.DEBUG, logger=logger.name):
                analyse("x = 1\ny = z")
        finally:
            logger.propagate = previous

        assert "constprop done" in caplog.text
        assert "constants=1" in caplog.text
        assert "symbols=2" in caplog.text
