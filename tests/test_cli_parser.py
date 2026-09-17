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

"""Tests pinning the CLI surface that ``build_parser`` produces.

The parser is assembled from shared option-group helpers, so these tests exist
to catch a helper change silently adding or dropping a flag on subcommands
that were not the one being edited.
"""

import argparse

import pytest

from mcpscanner.cli.parser import FORMAT_CHOICES, build_parser

EXPECTED_SUBCOMMANDS = [
    "static",
    "remote",
    "prompts",
    "resources",
    "instructions",
    "virustotal",
    "behavioral",
    "pypi-scan",
    "npm-scan",
    "vulnerable-package",
    "stdio",
    "config",
    "known-configs",
]

# Subcommands built on top of _add_output_options.
OUTPUT_OPTION_SUBCOMMANDS = [
    "virustotal",
    "behavioral",
    "pypi-scan",
    "npm-scan",
    "vulnerable-package",
]

# Subcommands built on top of _add_server_options.
SERVER_OPTION_SUBCOMMANDS = ["remote", "prompts", "resources", "instructions"]


@pytest.fixture(scope="module")
def parser():
    return build_parser()


@pytest.fixture(scope="module")
def subparsers(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    pytest.fail("parser exposes no subcommands")


def flags(p):
    return {s for action in p._actions for s in action.option_strings}


def action_for(p, flag):
    for action in p._actions:
        if flag in action.option_strings:
            return action
    raise AssertionError(f"{flag} not found")


class TestSubcommandRegistration:
    def test_every_subcommand_is_present_in_order(self, subparsers):
        # Order is asserted because argparse renders help in registration order.
        assert list(subparsers) == EXPECTED_SUBCOMMANDS


class TestSharedOutputOptions:
    @pytest.mark.parametrize("name", OUTPUT_OPTION_SUBCOMMANDS)
    def test_full_output_option_set(self, subparsers, name):
        assert {
            "--output",
            "-o",
            "--verbose",
            "-v",
            "--raw",
            "-r",
            "--detailed",
            "-d",
            "--format",
        } <= flags(subparsers[name])

    @pytest.mark.parametrize("name", OUTPUT_OPTION_SUBCOMMANDS)
    def test_format_defaults_to_summary(self, subparsers, name):
        action = action_for(subparsers[name], "--format")
        assert action.default == "summary"
        assert list(action.choices) == FORMAT_CHOICES


class TestSharedServerOptions:
    @pytest.mark.parametrize("name", SERVER_OPTION_SUBCOMMANDS)
    def test_server_url_is_required(self, subparsers, name):
        assert action_for(subparsers[name], "--server-url").required

    @pytest.mark.parametrize("name", SERVER_OPTION_SUBCOMMANDS)
    def test_bearer_token_is_accepted(self, subparsers, name):
        assert "--bearer-token" in flags(subparsers[name])

    def test_instructions_takes_no_custom_headers(self, subparsers):
        # instructions has no per-request body to attach headers to.
        assert "--header" not in flags(subparsers["instructions"])

    @pytest.mark.parametrize("name", ["remote", "prompts", "resources"])
    def test_header_is_repeatable_into_custom_headers(self, subparsers, name):
        action = action_for(subparsers[name], "--header")
        assert action.dest == "custom_headers"
        assert isinstance(action, argparse._AppendAction)


class TestStdioOptions:
    def test_subcommand_requires_a_command(self, subparsers):
        assert action_for(subparsers["stdio"], "--stdio-command").required

    def test_top_level_form_does_not(self, parser):
        # The flag-only invocation predates subcommands and must keep working.
        assert not action_for(parser, "--stdio-command").required

    def test_both_forms_share_the_same_launch_flags(self, parser, subparsers):
        launch = {
            "--stdio-command",
            "--stdio-args",
            "--stdio-arg",
            "--stderr-file",
            "--stdio-env",
            "--stdio-tool",
        }
        assert launch <= flags(parser)
        assert launch <= flags(subparsers["stdio"])


class TestPackageScanOptions:
    @pytest.mark.parametrize("name", ["pypi-scan", "npm-scan"])
    def test_sandbox_controls(self, subparsers, name):
        assert {"--version", "--rebuild-image", "--no-docker"} <= flags(
            subparsers[name]
        )

    @pytest.mark.parametrize("name", ["pypi-scan", "npm-scan"])
    def test_package_is_a_required_positional(self, subparsers, name):
        positionals = [
            a.dest for a in subparsers[name]._actions if not a.option_strings
        ]
        assert positionals == ["package"]

    def test_no_docker_help_names_the_right_ecosystem(self, subparsers):
        assert "PyPI" in action_for(subparsers["pypi-scan"], "--no-docker").help
        assert "npm" in action_for(subparsers["npm-scan"], "--no-docker").help


class TestParsing:
    def test_remote_subcommand_round_trips(self, parser):
        args = parser.parse_args(
            ["remote", "--server-url", "http://x", "--header", "A: b"]
        )
        assert args.cmd == "remote"
        assert args.server_url == "http://x"
        assert args.custom_headers == ["A: b"]

    def test_bare_invocation_uses_the_default_server(self, parser):
        args = parser.parse_args([])
        assert args.cmd is None
        assert args.server_url == "https://mcp.deepwiki.com/mcp"

    def test_mime_types_default_matches_between_static_and_resources(self, parser):
        static = parser.parse_args(["static", "--tools", "t.json"])
        resources = parser.parse_args(["resources", "--server-url", "http://x"])
        assert static.mime_types == resources.mime_types == "text/plain,text/html"
