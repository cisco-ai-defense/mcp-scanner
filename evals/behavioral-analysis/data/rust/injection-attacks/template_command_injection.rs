// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Unsafe template substitution composing a shell pipeline executed via bash -c.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::process::Command;

fn template_for(name: &str) -> &'static str {
    match name {
        "convert" => "convert $input_file $options $output_file",
        "process" => "$processor -i $input_file -o $output_file $flags",
        "analyze" => "$analyzer --input=$input_file --format=$format $extra_args",
        _ => "$command",
    }
}

fn template_placeholders(tmpl: &str) -> HashSet<String> {
    let mut keys = HashSet::new();
    let chars: Vec<char> = tmpl.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '$' {
            i += 1;
            continue;
        }
        if i + 1 < chars.len() && chars[i + 1] == '{' {
            i += 2;
            let mut name = String::new();
            while i < chars.len() && chars[i] != '}' {
                name.push(chars[i]);
                i += 1;
            }
            keys.insert(name.trim().to_string());
            if i < chars.len() {
                i += 1;
            }
            continue;
        }
        i += 1;
        let mut name = String::new();
        while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
            name.push(chars[i]);
            i += 1;
        }
        if !name.is_empty() {
            keys.insert(name);
        }
    }
    keys
}

fn render_template(tmpl: &str, vars: &HashMap<String, String>, strict: bool) -> Result<String, ()> {
    let chars: Vec<char> = tmpl.chars().collect();
    let mut i = 0usize;
    let mut out = String::new();
    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        if i + 1 < chars.len() && chars[i + 1] == '{' {
            i += 2;
            let mut name = String::new();
            while i < chars.len() && chars[i] != '}' {
                name.push(chars[i]);
                i += 1;
            }
            let key = name.trim().to_string();
            i += 1;
            match vars.get(&key) {
                Some(v) => out.push_str(v),
                None => {
                    if strict {
                        return Err(());
                    }
                    out.push('$');
                    out.push('{');
                    out.push_str(&key);
                    out.push('}');
                }
            }
            continue;
        }
        let start = i;
        i += 1;
        let mut name = String::new();
        while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
            name.push(chars[i]);
            i += 1;
        }
        if name.is_empty() {
            out.push(chars[start]);
            continue;
        }
        match vars.get(&name) {
            Some(v) => out.push_str(v),
            None => {
                if strict {
                    return Err(());
                }
                out.push('$');
                out.push_str(&name);
            }
        }
    }
    Ok(out)
}

fn build_command(template_name: &str, vars: &HashMap<String, String>) -> String {
    let tmpl = template_for(template_name);
    match render_template(tmpl, vars, true) {
        Ok(s) => s,
        Err(()) => render_template(tmpl, vars, false).unwrap_or_default(),
    }
}

struct ProcExec;

impl ProcExec {
    fn run_shell(command: &str) -> (i32, String, String) {
        match Command::new("bash").args(["-c", command]).output() {
            Ok(o) => (
                o.status.code().unwrap_or(1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            ),
            Err(e) => (1, String::new(), e.to_string()),
        }
    }
}

#[derive(Deserialize, JsonSchema)]
struct ProcessFileArgs {
    filepath: String,
    #[serde(default = "default_cat")] processor: String,
    #[serde(default = "default_tpl")] template_name: String,
    #[serde(default)] output_file: String,
    #[serde(default)] options: String,
    #[serde(default)] extra_args: String,
}

fn default_cat() -> String {
    "cat".to_string()
}
fn default_tpl() -> String {
    "process".to_string()
}

#[derive(Clone)]
struct TplSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl TplSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Process file with custom script using templated commands.
    #[tool(description = "Process file with custom script using templated commands.")]
    async fn process_file(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<ProcessFileArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut vars = HashMap::new();
        let out_file = if args.output_file.is_empty() {
            format!("{}.processed", args.filepath)
        } else {
            args.output_file.clone()
        };
        vars.insert("input_file".to_string(), args.filepath.clone());
        vars.insert("output_file".to_string(), out_file);
        vars.insert("processor".to_string(), args.processor.clone());
        vars.insert("command".to_string(), args.processor.clone());
        vars.insert("options".to_string(), args.options.clone());
        vars.insert("flags".to_string(), args.options.clone());
        vars.insert("extra_args".to_string(), args.extra_args.clone());
        vars.insert("format".to_string(), "json".to_string());
        vars.insert("analyzer".to_string(), args.processor.clone());

        let tmpl = template_for(&args.template_name);
        let _wanted = template_placeholders(tmpl);
        let command = build_command(&args.template_name, &vars);
        let (rc, _stdout, stderr) = ProcExec::run_shell(&command);

        if rc == 0 {
            let mut c = command.clone();
            if c.len() > 100 {
                c.truncate(100);
            }
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Processing complete. Command executed: {}...",
                c
            ))]))
        } else {
            let mut es = stderr;
            if es.len() > 200 {
                es.truncate(200);
            }
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Processing failed: {es}"
            ))]))
        }
    }
}

#[tool_handler]
impl ServerHandler for TplSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = TplSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
