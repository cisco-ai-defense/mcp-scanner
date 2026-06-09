# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for C#.

C# uses ``[McpServerTool]`` / ``[McpServerPrompt]`` /
``[McpServerResource]`` attributes from the .NET MCP SDK; bare
``[Tool]`` / ``[Prompt]`` / ``[Resource]`` only classify when the
trusted ``ModelContextProtocol`` namespaces are in scope.
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    assert_source_kind_tag,
)


HELPERS_ONLY = """\
public static class Helpers {
    public static double Normalize(double x) => x;
    public static double Helper(double a, double b) => a + b;
}
"""

MIXED = """\
using ModelContextProtocol.Server;
using System.ComponentModel;

[McpServerToolType]
public static class CalcTools
{
    private static double Normalize(double x) => x;

    [McpServerTool, Description("Add two numbers")]
    public static double Add(double a, double b) => Normalize(a) + Normalize(b);
}
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "Helpers.cs")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "Mixed.cs", {"CalcTools.Add"})


def test_source_kind_tag_is_annotation() -> None:
    assert_source_kind_tag(MIXED, "Mixed.cs", "<annotation>.tool")
