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

"""Tests for the Python parser.

Every Python analysis path starts here, so a node this misses is a node
no downstream analyzer can flag. The emphasis is on the accessors that
enumerate interesting constructs -- calls, imports, assignments -- and
on the naming of dotted calls, since a rule matching "os.system" depends
on the parser spelling it that way.
"""

import ast
import logging
from unittest.mock import patch

import pytest

from mcpscanner.core.static_analysis.parser.python_parser import PythonParser


def parser(source: str) -> PythonParser:
    return PythonParser("snippet.py", source)


def call(source: str) -> ast.Call:
    """The single Call node in an expression snippet."""
    return ast.parse(source, mode="eval").body


class TestParse:
    def test_valid_source_parses_to_a_module(self):
        assert isinstance(parser("x = 1").parse(), ast.Module)

    def test_ast_is_parsed_lazily_and_cached(self):
        p = parser("x = 1")
        assert p._ast is None
        first = p.get_ast()
        assert p._ast is not None
        assert p.get_ast() is first

    def test_syntax_error_names_the_file(self):
        with pytest.raises(SyntaxError, match="broken.py"):
            PythonParser("broken.py", "def (:").parse()

    def test_syntax_error_preserves_the_original_cause(self):
        with pytest.raises(SyntaxError) as exc:
            parser("def (:").parse()
        assert isinstance(exc.value.__cause__, SyntaxError)

    def test_syntax_error_is_logged_with_the_line(self, caplog):
        from mcpscanner.core.static_analysis.parser import python_parser

        logger = python_parser.logger
        previous = logger.propagate
        logger.propagate = True
        try:
            with caplog.at_level(logging.WARNING, logger=logger.name):
                with pytest.raises(SyntaxError):
                    parser("x = 1\ndef (:").parse()
        finally:
            logger.propagate = previous
        assert "syntax_error" in caplog.text
        assert "line=2" in caplog.text

    def test_empty_source_is_valid(self):
        assert parser("").get_function_calls() == []


class TestNodeRange:
    def test_range_tracks_the_node_position(self):
        p = parser("x = 1\ny = 2\n")
        assign = p.get_assignments()[1]
        r = p.get_node_range(assign)
        assert r.start.line == 2
        assert r.start.column == 0

    def test_multiline_node_spans_its_lines(self):
        p = parser("def f():\n    return 1\n")
        r = p.get_node_range(p.get_function_defs()[0])
        assert r.start.line == 1
        assert r.end.line == 2

    def test_node_without_a_position_yields_a_zero_range(self):
        """Module and operator nodes carry no lineno."""
        p = parser("x = 1")
        r = p.get_node_range(p.get_ast())
        assert (r.start.line, r.end.line) == (0, 0)


class TestNodeText:
    def test_text_round_trips_through_unparse(self):
        p = parser("result = compute(a, b)")
        assert p.get_node_text(p.get_assignments()[0]) == "result = compute(a, b)"

    def test_whole_module_unparses(self):
        assert parser("x = 1").get_node_text(parser("x = 1").get_ast()) == "x = 1"

    def test_unparseable_single_line_node_falls_back_to_slicing(self):
        p = parser("value = compute(a)")
        node = p.get_function_calls()[0]
        with patch("ast.unparse", side_effect=ValueError("cannot unparse")):
            assert p.get_node_text(node) == "compute(a)"

    def test_unparseable_multiline_node_falls_back_to_whole_lines(self):
        p = parser("def f():\n    return 1\n")
        node = p.get_function_defs()[0]
        with patch("ast.unparse", side_effect=ValueError("cannot unparse")):
            assert p.get_node_text(node) == "def f():\n    return 1"

    def test_unparseable_node_without_a_position_yields_empty(self):
        p = parser("x = 1")
        with patch("ast.unparse", side_effect=ValueError("cannot unparse")):
            assert p.get_node_text(p.get_ast()) == ""


class TestWalk:
    def test_walk_reaches_nested_nodes(self):
        p = parser("def f():\n    g()\n")
        assert any(isinstance(n, ast.Call) for n in p.walk())

    def test_walk_accepts_an_explicit_subtree(self):
        p = parser("def f():\n    g()\ndef h():\n    i()\n")
        only_f = p.walk(p.get_function_defs()[0])
        names = {n.id for n in only_f if isinstance(n, ast.Name)}
        assert names == {"g"}


class TestFunctionCalls:
    def test_all_calls_are_found(self):
        p = parser("a()\nb.c()\nd(e())\n")
        assert len(p.get_function_calls()) == 4

    def test_no_calls_in_plain_assignments(self):
        assert parser("x = 1").get_function_calls() == []

    def test_calls_nested_in_a_comprehension_are_found(self):
        assert len(parser("[f(i) for i in g()]").get_function_calls()) == 2

    def test_calls_in_a_decorator_are_found(self):
        p = parser("@app.tool()\ndef f():\n    pass\n")
        assert len(p.get_function_calls()) == 1


class TestAssignments:
    def test_plain_annotated_and_augmented_are_all_returned(self):
        p = parser("a = 1\nb: int = 2\nc += 3\n")
        assert len(p.get_assignments()) == 3

    def test_walrus_is_not_treated_as_an_assignment(self):
        """Documented limitation: NamedExpr is a distinct node type."""
        assert parser("if (n := f()):\n    pass\n").get_assignments() == []


class TestFunctionDefs:
    def test_sync_and_async_definitions_are_both_returned(self):
        p = parser("def a():\n    pass\nasync def b():\n    pass\n")
        assert {f.name for f in p.get_function_defs()} == {"a", "b"}

    def test_methods_and_nested_functions_are_included(self):
        p = parser(
            "class C:\n    def m(self):\n        def inner():\n            pass\n"
        )
        assert {f.name for f in p.get_function_defs()} == {"m", "inner"}

    def test_a_class_alone_yields_no_functions(self):
        assert parser("class C:\n    x = 1\n").get_function_defs() == []


class TestImports:
    def test_both_import_forms_are_returned(self):
        p = parser("import os\nfrom sys import argv\n")
        assert len(p.get_imports()) == 2

    def test_imports_inside_a_function_are_found(self):
        p = parser("def f():\n    import subprocess\n")
        assert len(p.get_imports()) == 1

    def test_no_imports_yields_empty(self):
        assert parser("x = 1").get_imports() == []


class TestNodeType:
    @pytest.mark.parametrize(
        "source,expected", [("f()", "Call"), ("x", "Name"), ("1", "Constant")]
    )
    def test_type_name_is_the_ast_class_name(self, source, expected):
        assert parser("").get_node_type(call(source)) == expected


class TestIsCallTo:
    def test_bare_call_matches_by_name(self):
        assert parser("").is_call_to(call("eval('x')"), "eval") is True

    def test_method_call_matches_on_the_attribute(self):
        assert parser("").is_call_to(call("os.system('ls')"), "system") is True

    def test_different_name_does_not_match(self):
        assert parser("").is_call_to(call("safe()"), "eval") is False

    def test_non_call_node_does_not_match(self):
        assert parser("").is_call_to(call("x"), "x") is False

    def test_a_computed_callee_does_not_match(self):
        assert parser("").is_call_to(call("handlers[0]()"), "handlers") is False


class TestCallName:
    @pytest.mark.parametrize(
        "source,expected",
        [
            ("eval('x')", "eval"),
            ("os.system('ls')", "os.system"),
            ("a.b.c.d()", "a.b.c.d"),
            ("subprocess.check_output([])", "subprocess.check_output"),
        ],
    )
    def test_dotted_paths_are_spelled_out_in_order(self, source, expected):
        """Rules match on names like "os.system", so the order matters."""
        assert parser("").get_call_name(call(source)) == expected

    def test_call_on_a_call_result_is_still_named(self):
        assert parser("").get_call_name(call("factory().run()")) == "run"

    def test_call_on_a_subscript_falls_back_to_source_text(self):
        assert parser("").get_call_name(call("handlers[0]()")) == "handlers[0]"


class TestDocstring:
    def test_function_docstring_is_extracted(self):
        p = parser('def f():\n    """What f does."""\n    pass\n')
        assert p.get_docstring(p.get_function_defs()[0]) == "What f does."

    def test_class_docstring_is_extracted(self):
        p = parser('class C:\n    """A class."""\n')
        cls = p.walk()[1]
        assert p.get_docstring(cls) == "A class."

    def test_module_docstring_is_extracted(self):
        p = parser('"""Module level."""\nx = 1\n')
        assert p.get_docstring(p.get_ast()) == "Module level."

    def test_function_without_a_docstring_returns_none(self):
        p = parser("def f():\n    pass\n")
        assert p.get_docstring(p.get_function_defs()[0]) is None

    def test_non_definition_node_returns_none(self):
        assert parser("").get_docstring(call("f()")) is None

    def test_empty_docstring_is_reported_as_absent(self):
        """ast.get_docstring returns "" here; the fallback also declines it."""
        p = parser('def f():\n    ""\n')
        assert p.get_docstring(p.get_function_defs()[0]) in (None, "")
