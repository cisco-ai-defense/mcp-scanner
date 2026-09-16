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

"""Tests for the bookkeeping shared by the capability extraction passes."""

import pytest

from mcpscanner.core.static_analysis.native_analyzer import (
    NativeAnalyzer,
    _CapabilityScan,
)


def make_scan():
    return _CapabilityScan(
        tree=None,
        imports=[],
        func_types=set(),
        import_target_map={},
        cross_file_analyzer=None,
    )


class TestCapabilityClaim:
    def test_first_claim_wins(self):
        scan = make_scan()

        assert scan.claim(100, "tool") is True

    def test_repeat_claim_is_refused(self):
        scan = make_scan()
        scan.claim(100, "tool")

        assert scan.claim(100, "tool") is False

    def test_same_handler_may_be_two_different_capabilities(self):
        # Registering one function as both a tool and a prompt is legal in
        # MCP, and must surface once per kind rather than being collapsed.
        scan = make_scan()

        assert scan.claim(100, "tool") is True
        assert scan.claim(100, "prompt") is True

    def test_handles_of_different_shapes_do_not_collide(self):
        # Passes key on whatever identifies the capability they found: a
        # start byte, a cross-file path, or a table entry.
        scan = make_scan()

        assert scan.claim(100, "tool") is True
        assert scan.claim("lib/add.ts::add", "tool") is True
        assert scan.claim("table:add", "tool") is True

    def test_claiming_records_into_seen(self):
        scan = make_scan()
        scan.claim(100, "tool")

        assert scan.seen == {(100, "tool")}


class TestRegistrationSourceKind:
    @pytest.mark.parametrize(
        "reg,qualifier,expected",
        [
            ({}, None, "registration"),
            ({}, "cross_file", "registration.cross_file"),
            ({}, "unresolved", "registration.unresolved"),
            ({"template_subtype": "template"}, None, "registration.template"),
            (
                {"template_subtype": "template"},
                "cross_file",
                "registration.cross_file.template",
            ),
            (
                {"template_subtype": "template"},
                "unresolved",
                "registration.unresolved.template",
            ),
        ],
    )
    def test_provenance_tag(self, reg, qualifier, expected):
        assert NativeAnalyzer._registration_source_kind(reg, qualifier) == expected

    def test_non_template_subtype_is_not_tagged(self):
        reg = {"template_subtype": "resource"}

        assert NativeAnalyzer._registration_source_kind(reg) == "registration"
