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

"""Negative tests for ``NativeAnalyzer.extract_mcp_capability_contexts``.

These pin the "looks-MCP-but-isn't" cases the previous implementation
classified as MCP via substring matching. With the exact-identifier
allow-list (Gap 3) and receiver verification (Gap 4) in place, none of
these should produce capability contexts.

If a future change reintroduces substring-style matching it will fail
here loudly rather than silently regressing detection precision.
"""

import pytest

from mcpscanner.core.static_analysis import NativeAnalyzer


# ---------------------------------------------------------------------------
# Annotation lookalikes — Gap 3 negative coverage.
# ---------------------------------------------------------------------------

JAVA_TOOLTIP_LOOKALIKE = """\
package demo;

import some.lib.Tooltip;

public class UI {
    @Tooltip("hover text")
    public void onClick() {}

    @ToolbarItem("save")
    public void onSave() {}
}
"""


CSHARP_RESOURCELOCK_LOOKALIKE = """\
using System;
using SomeLib;

public class Worker {
    [ResourceLock("/etc/passwd")]
    public void DoWork() {}

    [PromptUser("Are you sure?")]
    public bool Confirm() => true;
}
"""


RUST_TOOL_ROUTER_LOOKALIKE = """\
use some_lib::tool_router;

#[tool_router]
struct MyRouter;

impl MyRouter {
    #[setup_tool]
    fn helper(&self) -> u32 { 0 }
}
"""


PHP_TOOL_LOOKALIKE = """\
<?php

use SomeLib\\Toolbar;

class UI {
    #[Toolbar(name: "save")]
    public function save(): void {}
}
"""


@pytest.mark.parametrize(
    "source,path",
    [
        (JAVA_TOOLTIP_LOOKALIKE, "Lookalike.java"),
        (CSHARP_RESOURCELOCK_LOOKALIKE, "Lookalike.cs"),
        (RUST_TOOL_ROUTER_LOOKALIKE, "lookalike.rs"),
        (PHP_TOOL_LOOKALIKE, "lookalike.php"),
    ],
)
def test_annotation_lookalikes_yield_zero_capabilities(
    source: str, path: str
) -> None:
    """``@Tooltip``, ``[ResourceLock]``, ``#[tool_router]``,
    ``#[Toolbar]`` etc. must NOT classify as MCP capabilities (Gap 3).

    Although the prefilter only fires for tokens that genuinely belong
    to MCP SDKs, the per-language allow-list still has to reject these
    annotation strings if the prefilter happens to match.
    """
    analyzer = NativeAnalyzer(source, path)
    caps = analyzer.extract_mcp_capability_contexts()
    assert caps == [], (
        f"{path!r}: lookalike annotations classified as MCP capabilities: "
        f"{[c.name for c in caps]}"
    )


# ---------------------------------------------------------------------------
# Receiver verification — Gap 4 negative coverage.
# ---------------------------------------------------------------------------

NON_MCP_BUILDER_DSL_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Toolbar } from "./toolbar";

const server = new McpServer({ name: "demo", version: "1.0" });
const toolbar = new Toolbar();

// MCP — should classify
server.registerTool("real_tool", { description: "x" }, async () => {});

// Non-MCP — must NOT classify
toolbar.tool("save", () => {});
toolbar.registerPrompt("noop", () => {});
"""


def test_non_mcp_dsl_does_not_classify_when_mcp_import_present() -> None:
    """When a file imports ``McpServer`` AND uses an unrelated builder DSL,
    only the MCP server's registrations are accepted (Gap 4)."""
    analyzer = NativeAnalyzer(NON_MCP_BUILDER_DSL_TS, "mixed_dsl.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    names = {c.name for c in caps}
    # ``real_tool`` must be present, ``save`` and ``noop`` must not.
    assert "real_tool" in names, names
    assert "save" not in names, names
    assert "noop" not in names, names


JAVA_NON_MCP_TOOL_LOOKALIKE = """\
package demo;

import org.junit.ToolProvider;

@ToolProvider
public class JUnitToolProvider {
    public void register() {}
}
"""


def test_junit_toolprovider_does_not_classify() -> None:
    """JUnit ``@ToolProvider`` is a different namespace from Spring AI MCP
    and must NOT classify as a tool (Gap 3 generic-leaf trust check)."""
    analyzer = NativeAnalyzer(JAVA_NON_MCP_TOOL_LOOKALIKE, "JUnit.java")
    caps = analyzer.extract_mcp_capability_contexts()
    assert caps == [], [c.name for c in caps]
