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

"""Tests for the argv that stdio MCP servers are launched with.

Everything here decides what process runs and with which arguments, so
the cases worth pinning are the ones where a value could land in the
wrong place: a command that gets split when it should not, an
unset variable that silently becomes empty, a relative path that
resolves off PATH.
"""

import os
from unittest.mock import patch

import pytest

from mcpscanner.utils.command_utils import (
    build_env_for_expansion,
    decide_windows_semantics,
    expand_text,
    normalize_and_expand_command_args,
    resolve_executable_path,
    split_embedded_args,
)


class TestBuildEnvForExpansion:
    def test_server_env_overrides_os_env(self):
        with patch.dict(os.environ, {"SHARED": "from_os"}, clear=False):
            merged = build_env_for_expansion({"SHARED": "from_server"})
        assert merged["SHARED"] == "from_server"

    def test_os_env_is_inherited_when_server_env_is_none(self):
        with patch.dict(os.environ, {"ONLY_IN_OS": "yes"}, clear=False):
            assert build_env_for_expansion(None)["ONLY_IN_OS"] == "yes"

    def test_non_string_values_are_coerced(self):
        """Server configs come from JSON, where ports arrive as ints."""
        merged = build_env_for_expansion({"PORT": 8080, "DEBUG": True, "NOTHING": None})
        assert merged["PORT"] == "8080"
        assert merged["DEBUG"] == "True"
        assert merged["NOTHING"] == "None"

    def test_every_value_is_a_string(self):
        merged = build_env_for_expansion({"A": 1, "B": 2.5})
        assert all(isinstance(v, str) for v in merged.values())


class TestDecideWindowsSemantics:
    @pytest.mark.parametrize(
        "mode,expected",
        [("windows", True), ("linux", False), ("mac", False), ("WINDOWS", True)],
    )
    def test_explicit_modes_ignore_the_host(self, mode, expected):
        assert decide_windows_semantics(mode) is expected

    @pytest.mark.parametrize("mode", ["auto", "off", "", None, "nonsense"])
    def test_unset_and_unknown_modes_follow_the_host(self, mode):
        assert decide_windows_semantics(mode) is (os.name == "nt")


class TestExpandText:
    def test_empty_input_returns_empty(self):
        assert expand_text("", {}, "linux") == ""

    def test_off_mode_leaves_variables_alone(self):
        assert expand_text("$HOME/bin", {"HOME": "/h"}, "off") == "$HOME/bin"

    def test_off_mode_still_expands_tilde(self):
        assert expand_text("~", {}, "off") == os.path.expanduser("~")

    def test_posix_variable_is_expanded(self):
        assert expand_text("$TOKEN", {"TOKEN": "abc123"}, "linux") == "abc123"

    def test_braced_posix_variable_is_expanded(self):
        assert expand_text("${TOKEN}x", {"TOKEN": "abc"}, "linux") == "abcx"

    def test_surrounding_whitespace_is_stripped(self):
        assert expand_text("  spaced  ", {}, "off") == "spaced"

    def test_os_environ_is_restored_after_expansion(self):
        """Expansion temporarily mutates os.environ; it must put it back."""
        before = dict(os.environ)
        expand_text("$EPHEMERAL", {"EPHEMERAL": "tmp"}, "linux")
        assert dict(os.environ) == before
        assert "EPHEMERAL" not in os.environ

    def test_os_environ_is_restored_even_when_expansion_raises(self):
        before = dict(os.environ)
        with patch(
            "mcpscanner.utils.command_utils._expandvars_lib",
            side_effect=RuntimeError("boom"),
        ):
            expand_text("$X", {"X": "1"}, "linux")
        assert dict(os.environ) == before

    def test_expansion_failure_falls_back_instead_of_raising(self):
        with patch(
            "mcpscanner.utils.command_utils._expandvars_lib",
            side_effect=RuntimeError("boom"),
        ):
            assert expand_text("plain", {}, "linux") == "plain"

    def test_windows_style_variable_is_expanded(self):
        assert expand_text("%TOKEN%", {"TOKEN": "abc"}, "windows") == "abc"

    def test_windows_expansion_leaves_no_stray_delimiter(self):
        """Regression: expandvars used to yield 'abc%' here."""
        assert (
            expand_text("%A%\\bin", {"A": "C:\\tools"}, "windows") == "C:\\tools\\bin"
        )

    def test_multiple_windows_variables_in_one_string(self):
        out = expand_text("%A%-%B%", {"A": "one", "B": "two"}, "windows")
        assert out == "one-two"

    def test_unknown_windows_variable_is_left_alone(self):
        """cmd.exe leaves an undefined %VAR% as written rather than blanking it."""
        assert expand_text("%MISSING%", {}, "windows") == "%MISSING%"

    def test_posix_syntax_is_not_expanded_under_windows_mode(self):
        assert expand_text("$TOKEN", {"TOKEN": "abc"}, "windows") == "$TOKEN"


class TestNormalizeAndExpandCommandArgs:
    def test_command_and_args_are_both_expanded(self):
        cmd, args = normalize_and_expand_command_args(
            "$RUNNER",
            ["--token", "$TOKEN"],
            {"RUNNER": "node", "TOKEN": "s3cret"},
            "linux",
        )
        assert cmd == "node"
        assert args == ["--token", "s3cret"]

    def test_none_args_becomes_empty_list(self):
        cmd, args = normalize_and_expand_command_args("node", None, {}, "off")
        assert (cmd, args) == ("node", [])

    def test_empty_command_is_tolerated(self):
        cmd, args = normalize_and_expand_command_args(None, [], {}, "off")
        assert cmd == ""


class TestSplitEmbeddedArgs:
    def test_command_with_spaces_and_no_args_is_split(self):
        cmd, args = split_embedded_args("npx -y server", [], windows_semantics=False)
        assert cmd == "npx"
        assert args == ["-y", "server"]

    def test_existing_args_suppress_splitting(self):
        """A path with a space must not be torn apart when args were given."""
        cmd, args = split_embedded_args(
            "/opt/my server/bin", ["--flag"], windows_semantics=False
        )
        assert cmd == "/opt/my server/bin"
        assert args == ["--flag"]

    def test_quoted_segments_survive_splitting(self):
        cmd, args = split_embedded_args(
            '"/opt/my server/node" --flag', [], windows_semantics=False
        )
        assert cmd == "/opt/my server/node"
        assert args == ["--flag"]

    def test_tab_separated_command_is_split(self):
        cmd, args = split_embedded_args("node\tserver.js", [], windows_semantics=False)
        assert cmd == "node"
        assert args == ["server.js"]

    def test_plain_command_is_untouched(self):
        assert split_embedded_args("node", [], windows_semantics=False) == ("node", [])

    def test_whitespace_only_command_yields_no_parts(self):
        cmd, args = split_embedded_args("   ", [], windows_semantics=False)
        assert cmd == "   "
        assert args == []


class TestResolveExecutablePath:
    def test_empty_command_resolves_to_nothing(self):
        assert resolve_executable_path("") is None
        assert resolve_executable_path(None) is None
        assert resolve_executable_path("   ") is None

    def test_surrounding_quotes_are_stripped(self, tmp_path):
        exe = tmp_path / "runner"
        exe.write_text("#!/bin/sh\n")
        assert resolve_executable_path(f'"{exe}"') == str(exe)
        assert resolve_executable_path(f"'{exe}'") == str(exe)

    def test_existing_absolute_path_is_returned_as_is(self, tmp_path):
        exe = tmp_path / "runner"
        exe.write_text("#!/bin/sh\n")
        assert resolve_executable_path(str(exe)) == str(exe)

    def test_absolute_path_that_does_not_exist_falls_back_to_path_lookup(self):
        assert resolve_executable_path("/nonexistent/dir/definitely-not-here") is None

    def test_bare_name_is_looked_up_on_path(self):
        import shutil

        assert resolve_executable_path("sh") == shutil.which("sh")

    def test_unknown_bare_name_resolves_to_nothing(self):
        assert resolve_executable_path("definitely-not-a-real-binary-xyz") is None
