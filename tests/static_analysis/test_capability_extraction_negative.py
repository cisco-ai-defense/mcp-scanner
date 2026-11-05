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


# ---------------------------------------------------------------------------
# Sink matching — shared-leaf negative coverage.
# ---------------------------------------------------------------------------

RUST_SHARED_LEAF_CONSTRUCTORS = """\
use std::ffi::CString;
use uuid::Uuid;

#[tool]
pub fn make_label(value: String) -> String {
    let c = CString::new(value).unwrap();
    let _id = Uuid::new_v4();
    c.into_string().unwrap()
}
"""


RUST_REAL_SINKS = """\
#[tool]
pub fn run_shell(value: String) -> String {
    let out = std::process::Command::new("sh").arg("-c").arg(value).output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[tool]
pub fn load_plugin(path: String) {
    unsafe { libloading::Library::new(path).unwrap(); }
}
"""


def test_shared_constructor_leaf_is_not_a_subprocess_sink() -> None:
    """``CString::new`` shares its leaf with ``Command::new`` but is unrelated.

    Matching a qualified call on its leaf alone made every ``::new`` in Rust
    look like process execution.
    """
    analyzer = NativeAnalyzer(RUST_SHARED_LEAF_CONSTRUCTORS, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    label = funcs["make_label"]
    assert not label.has_subprocess_calls, "CString::new flagged as subprocess"
    assert not label.has_eval_exec, "CString::new flagged as dynamic code load"


RUST_STRING_NEW_BESIDE_PLUGIN_NEW = """\
use libloading::Library;
use rmcp::{tool, tool_router};

struct Plugin;

impl Plugin {
    fn new(path: &str) -> String {
        unsafe { Library::new(path).unwrap(); }
        path.to_string()
    }

    fn from(path: &str) -> String {
        unsafe { Library::new(path).unwrap(); }
        path.to_string()
    }
}

struct Svc;

#[tool_router]
impl Svc {
    #[tool(description = "Build an empty label.")]
    fn make_label(&self, plugin_path: String) -> String {
        let _label = String::new();
        let _owned = String::from(plugin_path);
        plugin_path
    }
}
"""


RUST_STRING_NEW_BESIDE_BARE_NEW = """\
use libloading::Library;
use rmcp::{tool, tool_router};

fn new(path: &str) -> String {
    unsafe { Library::new(path).unwrap(); }
    path.to_string()
}

struct Svc;

#[tool_router]
impl Svc {
    #[tool(description = "Build an empty label.")]
    fn make_label(&self, plugin_path: String) -> String {
        let _label = String::new();
        plugin_path
    }
}
"""


def test_rust_foreign_type_path_does_not_resolve_to_local_method() -> None:
    """``String::new`` must not inherit a local ``Plugin::new`` sink.

    The same leaf also must not mark the tool parameter as reaching that
    method when the call is ``String::from``.
    """
    analyzer = NativeAnalyzer(RUST_STRING_NEW_BESIDE_PLUGIN_NEW, "lib.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    reachable = ctx.reachable_functions or []
    assert ctx.has_eval_exec is False
    assert "Plugin.new" not in reachable
    assert "Plugin.from" not in reachable
    flow = next(
        (
            item
            for item in ctx.parameter_flows
            if item.get("parameter_name") == "plugin_path"
        ),
        None,
    )
    assert flow is not None, ctx.parameter_flows
    assert flow["reaches_external"] is False, flow


RUST_LIBLOADING_PATH_BESIDE_LOCAL_LIBRARY = """\
use std::process::Command;
use rmcp::{tool, tool_router};

struct Library;

impl Library {
    fn new(command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }
}

struct Svc;

#[tool_router]
impl Svc {
    #[tool(description = "Load a plugin module from the plugins directory.")]
    fn load_plugin(&self, plugin_path: String) -> String {
        unsafe { libloading::Library::new(plugin_path.as_str()).unwrap(); }
        plugin_path
    }
}
"""


def test_rust_external_crate_path_does_not_resolve_to_local_type() -> None:
    """``libloading::Library::new`` must not bind to a local ``Library::new``."""
    analyzer = NativeAnalyzer(RUST_LIBLOADING_PATH_BESIDE_LOCAL_LIBRARY, "lib.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is False
    assert "Library.new" not in (ctx.reachable_functions or [])


def test_rust_foreign_type_path_does_not_resolve_to_bare_function() -> None:
    """``String::new`` must not bind to a top-level ``fn new``."""
    analyzer = NativeAnalyzer(RUST_STRING_NEW_BESIDE_BARE_NEW, "lib.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_eval_exec is False
    assert "new" not in (ctx.reachable_functions or [])


RUST_SELF_CALLS_THE_SAFE_IMPL = """\
use std::process::Command;
use rmcp::{tool, tool_router};

struct Other;

impl Other {
    fn execute_command(command: &str) -> i32 {
        match Command::new("sh").arg("-c").arg(command).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(_) => 1,
        }
    }
}

struct Svc;

#[tool_router]
impl Svc {
    fn execute_command(command: &str) -> i32 {
        command.len() as i32
    }

    #[tool(description = "Measure a command string.")]
    fn execute_shell_command(&self, command: String) -> i32 {
        Self::execute_command(&command)
    }
}
"""


RUST_LIBRARY_NEW_WITHOUT_IMPORT = """\
use rmcp::{tool, tool_router};

struct Svc;

#[tool_router]
impl Svc {
    #[tool(description = "Load a plugin module from the plugins directory.")]
    fn load_plugin(&self, plugin_path: String) -> String {
        unsafe { Library::new(plugin_path).unwrap(); }
        plugin_path
    }
}
"""


def test_rust_self_does_not_inherit_another_impls_shell_sink() -> None:
    """A same-named helper on a different type is not this tool's callee."""
    analyzer = NativeAnalyzer(RUST_SELF_CALLS_THE_SAFE_IMPL, "shell.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    ctx = caps[0]
    assert ctx.has_subprocess_calls is False
    assert "Svc.execute_command" in (ctx.reachable_functions or [])
    assert "Other.execute_command" not in (ctx.reachable_functions or [])


def test_python_execute_method_is_not_dynamic_import() -> None:
    """A method named ``execute`` is not ``exec`` or ``exec_module``."""
    source = "def run(loader, data):\n    return loader.execute(data)\n"
    analyzer = NativeAnalyzer(source, "run.py")
    func = analyzer.analyze().functions[0]
    assert func.has_eval_exec is False


def test_go_os_open_is_not_plugin_open() -> None:
    """``os.Open`` is file I/O. Only ``plugin.Open`` is dynamic loading."""
    source = """\
package main

import "os"

func readFile(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    f.Close()
    return nil
}
"""
    analyzer = NativeAnalyzer(source, "read.go")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["readFile"].has_eval_exec is False


def test_go_bare_open_is_not_plugin_open() -> None:
    """``plugin.Open`` must not flag an unqualified ``Open()`` call."""
    source = """\
package main

func Open(path string) {}

func readFile(path string) {
    Open(path)
}
"""
    analyzer = NativeAnalyzer(source, "open.go")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["readFile"].has_eval_exec is False


def test_js_plain_loader_alias_is_not_create_require() -> None:
    """Only an alias of ``createRequire(...)`` is a dynamic module load."""
    source = """\
const requireModule = (p) => p;
function load_plugin(plugin_path) {
  return requireModule(plugin_path);
}
"""
    analyzer = NativeAnalyzer(source, "load.js")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False


def test_unimported_library_new_is_not_dynamic_loading() -> None:
    """``Library::new`` is only the libloading sink after that type is imported."""
    analyzer = NativeAnalyzer(RUST_LIBRARY_NEW_WITHOUT_IMPORT, "lib.rs")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert caps[0].has_eval_exec is False
    assert caps[0].has_subprocess_calls is False


def test_qualified_rust_sinks_still_detected() -> None:
    """Tightening the matcher must not lose the real sinks it guards."""
    analyzer = NativeAnalyzer(RUST_REAL_SINKS, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["run_shell"].has_subprocess_calls
    # ``libloading::Library::new`` is dynamic code loading, not a subprocess.
    assert funcs["load_plugin"].has_eval_exec
    assert not funcs["load_plugin"].has_subprocess_calls


def test_unrelated_import_module_method_is_not_dynamic_loading() -> None:
    """``import_module`` is not a leaf sink. Only importlib aliases count."""
    source = (
        "def load(custom_loader, name):\n"
        "    return custom_loader.import_module(name)\n"
    )
    analyzer = NativeAnalyzer(source, "load.py")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load"].has_eval_exec is False


def test_import_module_alias_from_another_module_is_not_importlib() -> None:
    """A renamed import counts only when it comes from ``importlib``."""
    source = (
        "from otherlib import import_module as load_mod\n"
        "def load(name):\n"
        "    return load_mod(name)\n"
    )
    analyzer = NativeAnalyzer(source, "load.py")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load"].has_eval_exec is False


def test_importlib_util_alias_does_not_bind_import_module() -> None:
    """``import importlib.util as util`` does not make ``util`` importlib."""
    source = (
        "import importlib.util as util\n"
        "def load(name):\n"
        "    return util.import_module(name)\n"
    )
    analyzer = NativeAnalyzer(source, "load.py")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load"].has_eval_exec is False


def test_python_importlib_spec_construction_is_not_execution() -> None:
    """Building a module spec does not run it. ``exec_module`` does."""
    spec_only = (
        "import importlib.util\n"
        "def load(path):\n"
        "    return importlib.util.spec_from_file_location('plugin', path)\n"
    )
    module_only = (
        "import importlib.util\n"
        "def load(spec):\n"
        "    return importlib.util.module_from_spec(spec)\n"
    )
    for source in (spec_only, module_only):
        analyzer = NativeAnalyzer(source, "load.py")
        funcs = {f.name: f for f in analyzer.analyze().functions}
        assert funcs["load"].has_eval_exec is False


def test_rust_bare_new_is_not_a_sink() -> None:
    """``new()`` is not ``Command::new`` or ``libloading::Library::new``."""
    source = "fn build() {\n    new();\n}\n"
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["build"].has_subprocess_calls is False
    assert funcs["build"].has_eval_exec is False


def test_unrelated_rust_glob_does_not_bind_library() -> None:
    """``use serde::*`` does not make ``Library::new`` a libloading sink."""
    source = (
        "use serde::*;\n"
        "fn load_plugin(path: &str) {\n"
        "    unsafe { Library::new(path); }\n"
        "}\n"
    )
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False


def test_rust_glob_does_not_escape_its_scope() -> None:
    """A ``use`` glob stays in its function, block, or module."""
    source = """\
struct Library;

fn load_plugin(path: &str) {
    use libloading::*;
    unsafe { Library::new(path); }
}

fn safe(path: &str) {
    unsafe { Library::new(path); }
}

fn inner_only(path: &str) {
    {
        use libloading::*;
        unsafe { Library::new(path); }
    }
}

fn after_block(path: &str) {
    {
        use libloading::*;
    }
    unsafe { Library::new(path); }
}

mod plugins {
    use libloading::*;
    pub fn load_in_mod(path: &str) {
        unsafe { Library::new(path); }
    }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is True
    assert funcs["safe"].has_eval_exec is False
    assert funcs["inner_only"].has_eval_exec is True
    assert funcs["after_block"].has_eval_exec is False
    assert funcs["load_in_mod"].has_eval_exec is True


def test_rust_module_glob_is_hidden_by_local_type() -> None:
    """A struct named ``Library`` hides ``use libloading::*`` in that module."""
    source = """\
use libloading::*;

struct Library;

fn load_plugin(path: &str) {
    unsafe { Library::new(path); }
}

mod plugins {
    use libloading::*;
    pub fn load_in_mod(path: &str) {
        unsafe { Library::new(path); }
    }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False
    assert funcs["load_in_mod"].has_eval_exec is True

    local_struct = """\
use libloading::*;

fn safe(path: &str) {
    struct Library;
    unsafe { Library::new(path); }
}

fn load_plugin(path: &str) {
    unsafe { Library::new(path); }
}
"""
    analyzer = NativeAnalyzer(local_struct, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["safe"].has_eval_exec is False
    assert funcs["load_plugin"].has_eval_exec is True


def test_rust_explicit_use_stays_in_its_scope() -> None:
    """An explicit ``use`` does not leak, and a type hides it in that scope."""
    source = """\
fn load_plugin(path: &str) {
    use libloading::Library;
    unsafe { Library::new(path); }
}

fn safe(path: &str) {
    unsafe { Library::new(path); }
}

mod plugins {
    use libloading::Library;
    pub fn load_in_mod(path: &str) {
        unsafe { Library::new(path); }
    }
}

fn decoy(path: &str) {
    use other::Library;
    let _ = path;
}

fn load_via_glob(path: &str) {
    use libloading::*;
    unsafe { Library::new(path); }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is True
    assert funcs["safe"].has_eval_exec is False
    assert funcs["load_in_mod"].has_eval_exec is True
    assert funcs["load_via_glob"].has_eval_exec is True

    hidden = """\
use libloading::Library;

struct Library;

fn load_plugin(path: &str) {
    unsafe { Library::new(path); }
}

fn load_inside(path: &str) {
    use libloading::Library;
    unsafe { Library::new(path); }
}
"""
    analyzer = NativeAnalyzer(hidden, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False
    assert funcs["load_inside"].has_eval_exec is True


def test_reexported_library_is_not_libloading() -> None:
    """``foo::libloading::Library`` is not the libloading crate."""
    grouped = """\
use foo::{libloading::Library};

fn load_plugin(path: &str) {
    unsafe { Library::new(path); }
}
"""
    full = """\
use foo::libloading::Library;

fn load_plugin(path: &str) {
    unsafe { Library::new(path); }
}
"""
    written = """\
fn load_plugin(path: &str) {
    unsafe { foo::libloading::Library::new(path); }
}
"""
    absolute = """\
fn load_plugin(path: &str) {
    unsafe { ::foo::libloading::Library::new(path); }
}
"""
    for source in (grouped, full, written, absolute):
        analyzer = NativeAnalyzer(source, "lib.rs")
        funcs = {f.name: f for f in analyzer.analyze().functions}
        assert funcs["load_plugin"].has_eval_exec is False


def test_same_scope_explicit_use_beats_glob() -> None:
    """An explicit import in the same block hides ``use libloading::*``."""
    source = """\
fn load_plugin(path: &str) {
    use other::Library;
    use libloading::*;
    unsafe { Library::new(path); }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False


def test_same_scope_type_still_hides_glob() -> None:
    """A struct hides a glob in that same block, even inside an outer use."""
    source = """\
use other::Library;

fn load_plugin(path: &str) {
    struct Library;
    use libloading::*;
    unsafe { Library::new(path); }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False


def test_reexported_fs_path_is_not_a_file_sink() -> None:
    """A ``foo::`` prefix is not ``fs::File::open`` or ``tokio::fs::File::open``."""
    sources = (
        """\
fn read_it(path: &str) {
    let _ = foo::fs::File::open(path);
}
""",
        """\
fn read_it(path: &str) {
    let _ = ::foo::fs::File::open(path);
}
""",
        """\
fn read_it(path: &str) {
    let _ = ::foo::tokio::fs::File::open(path);
}
""",
        """\
fn read_it(path: &str) {
    let _ = foo::tokio::fs::File::open(path);
}
""",
        """\
use foo::tokio::fs::File;

fn read_it(path: &str) {
    let _ = File::open(path);
}
""",
    )
    for source in sources:
        analyzer = NativeAnalyzer(source, "lib.rs")
        funcs = {f.name: f for f in analyzer.analyze().functions}
        assert funcs["read_it"].has_file_operations is False


def test_crate_root_leaf_is_not_a_std_sink() -> None:
    """A one-segment ``::name()`` call is not the standard-library sink."""
    source = """\
fn read_it(path: &str) {
    let _ = ::read(path);
}

fn write_it(path: &str) {
    let _ = ::write(path);
}

fn open_it(path: &str) {
    let _ = ::open(path);
}

fn create_it(path: &str) {
    let _ = ::create(path);
}

fn read_text(path: &str) {
    let _ = ::read_to_string(path);
}

fn run_shell(cmd: &str) {
    let _ = ::Command(cmd);
}

fn fetch(url: &str) {
    let _ = ::get(url);
}

fn send(url: &str) {
    let _ = ::post(url);
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    for name in ("read_it", "write_it", "open_it", "create_it", "read_text"):
        assert funcs[name].has_file_operations is False
    assert funcs["run_shell"].has_subprocess_calls is False
    assert funcs["fetch"].has_network_operations is False
    assert funcs["send"].has_network_operations is False


def test_local_module_hides_the_relative_sink_path() -> None:
    """``mod libloading`` owns ``libloading::Library::new`` in that module."""
    source = """\
mod libloading {
    pub struct Library;
    impl Library {
        pub fn new(_path: &str) -> Self { Library }
    }
}

fn load_plugin(path: &str) {
    libloading::Library::new(path);
}

mod other {
    pub fn load_extern(path: &str) {
        unsafe { libloading::Library::new(path); }
    }
}

fn load_inside(path: &str) {
    mod fs {
        pub struct File;
        impl File {
            pub fn open(_path: &str) -> Self { File }
        }
    }
    let _ = fs::File::open(path);
}

fn read_std(path: &str) {
    let _ = std::fs::File::open(path);
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False
    assert funcs["load_extern"].has_eval_exec is True
    assert funcs["load_inside"].has_file_operations is False
    assert funcs["read_std"].has_file_operations is True


def test_use_of_a_local_module_is_not_the_extern_crate() -> None:
    """``use libloading::Library`` follows the local module."""
    source = """\
mod libloading {
    pub struct Library;
    impl Library {
        pub fn new(_path: &str) -> Self { Library }
        pub fn marker(&self) -> u8 { 1 }
    }
}

fn load_plugin(path: &str) -> u8 {
    use libloading::Library;
    Library::new(path).marker()
}

fn load_glob(path: &str) {
    use libloading::*;
    Library::new(path);
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False
    assert funcs["load_glob"].has_eval_exec is False


def test_inner_module_still_hides_an_outer_use() -> None:
    """A module in the function body beats an outer ``use`` of that name."""
    source = """\
use std::fs::File;

fn read_it(path: &str) {
    mod File {
        pub struct File;
        impl File {
            pub fn open(_path: &str) -> Self { File }
        }
    }
    let _ = File::open(path);
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["read_it"].has_file_operations is False


def test_written_path_inside_a_local_module_stays_local() -> None:
    """``std::fs::File::open`` beside ``mod std`` is that module."""
    source = """\
fn read_it(path: &str) {
    {
        mod std { pub struct X; }
        let _ = std::fs::File::open(path);
    }
}

fn load_plugin(path: &str) {
    mod libloading {
        pub struct Library;
        impl Library {
            pub fn new(_path: &str) -> Self { Library }
        }
    }
    use libloading::Library;
    {
        unsafe { Library::new(path); }
    }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["read_it"].has_file_operations is False
    assert funcs["load_plugin"].has_eval_exec is False


def test_function_use_does_not_leak_into_a_nested_module() -> None:
    """A ``use`` in a function does not apply inside a nested ``mod``."""
    source = """\
fn read_it(path: &str) {
    use std::fs::File;
    mod child {
        pub fn read_child(path: &str) {
            let _ = File::open(path);
        }
    }
}

fn read_glob(path: &str) {
    use std::fs::*;
    mod child {
        pub fn read_glob_child(path: &str) {
            let _ = File::open(path);
        }
    }
}

fn load_plugin(path: &str) {
    use libloading::Library;
    mod child {
        pub fn load_child(path: &str) {
            unsafe { Library::new(path); }
        }
    }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["read_it"].has_file_operations is False
    assert funcs["read_child"].has_file_operations is False
    assert funcs["read_glob"].has_file_operations is False
    assert funcs["read_glob_child"].has_file_operations is False
    assert funcs["load_plugin"].has_eval_exec is False
    assert funcs["load_child"].has_eval_exec is False


def test_crate_root_call_does_not_follow_a_use() -> None:
    """``::Library`` is not the ``Library`` imported in this file."""
    lib = """\
use libloading::Library;

fn load_plugin(path: &str) {
    unsafe { ::Library::new(path); }
}

fn load_relative(path: &str) {
    unsafe { Library::new(path); }
}
"""
    analyzer = NativeAnalyzer(lib, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False
    assert funcs["load_relative"].has_eval_exec is True

    opened = """\
use std::fs::File;

fn read_it(path: &str) {
    let _ = ::File::open(path);
}

fn read_relative(path: &str) {
    let _ = File::open(path);
}
"""
    analyzer = NativeAnalyzer(opened, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["read_it"].has_file_operations is False
    assert funcs["read_relative"].has_file_operations is True


def test_unrelated_libloading_glob_prefix_is_not_the_sink() -> None:
    """``use foo::libloading::*`` is not ``libloading::Library::new``."""
    source = """\
use foo::libloading::*;

fn load_plugin(path: &str) {
    unsafe { Library::new(path); }
}
"""
    analyzer = NativeAnalyzer(source, "lib.rs")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load_plugin"].has_eval_exec is False


def test_other_create_require_is_not_dynamic_loading() -> None:
    """Only ``createRequire`` and ``module.createRequire`` are the factory."""
    source = """\
function load(pluginPath) {
  return other.createRequire(import.meta.url)(pluginPath);
}
function local(pluginPath) {
  const createRequire = (x) => x;
  return createRequire(import.meta.url)(pluginPath);
}
function factory(pluginPath) {
  const req = createRequire;
  return req(import.meta.url);
}
"""
    analyzer = NativeAnalyzer(source, "load.js")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load"].has_eval_exec is False
    assert funcs["local"].has_eval_exec is False
    assert funcs["factory"].has_eval_exec is False


def test_create_require_factory_alone_is_not_a_load() -> None:
    """Calling ``createRequire`` without invoking the result does not load."""
    source = (
        "function load(pluginPath) {\n"
        "  createRequire(import.meta.url);\n"
        "  return pluginPath;\n"
        "}\n"
    )
    analyzer = NativeAnalyzer(source, "load.js")
    funcs = {f.name: f for f in analyzer.analyze().functions}
    assert funcs["load"].has_eval_exec is False
