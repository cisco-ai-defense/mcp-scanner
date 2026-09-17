# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for PHP.

PHP detection is annotation-driven via php-mcp/server attribute
shapes (``#[Tool]`` / ``#[McpTool]`` / ``#[Prompt]`` / ``#[Resource]``).
The PHP namespace separator is ``\\`` rather than ``.``; the trusted
namespaces in
:data:`mcpscanner.core.static_analysis.capability.php.PhpAdapter.TRUSTED_NAMESPACES`
list ``PhpMcp`` / ``PhpMcp\\Server`` / ``PhpMcp\\Server\\Attributes``
to match real-world imports.
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    assert_source_kind_tag,
)


HELPERS_ONLY = """\
<?php
class Helpers {
    public function normalize(float $x): float { return $x; }
    public function helper(float $a, float $b): float { return $a + $b; }
}
"""

MIXED = """\
<?php

use PhpMcp\\Server\\Attributes\\McpTool;

class Calc {
    private function helper(float $x): float { return $x; }

    #[McpTool(name: "add", description: "Add two numbers")]
    public function add(float $a, float $b): float {
        return $this->helper($a) + $this->helper($b);
    }
}
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "helpers.php")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "mixed.php", {"Calc.add"})


def test_source_kind_tag_is_annotation() -> None:
    assert_source_kind_tag(MIXED, "mixed.php", "<annotation>.tool")
