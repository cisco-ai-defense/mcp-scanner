// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Template / command substitution — loosely validated string.Template analogues chained to shell exec.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "node:child_process";

const SCRIPT_TEMPLATES = {
  convert: "convert $input_file $options $output_file",
  process: "$processor -i $input_file -o $output_file $flags",
  analyze: "$analyzer --input=$input_file --format=$format $extra_args",
  custom: "$command",
};

function buildCommand(templateName, variables) {
  const tmpl = SCRIPT_TEMPLATES[templateName] ?? SCRIPT_TEMPLATES.custom;

  try {
    return tmpl.replace(/\$(\w+)|\$\{(\w+)\}/g, (_, a, b) => {
      const key = a || b;
      if (!(Object.prototype.hasOwnProperty.call(variables, key))) throw new Error("KeyError");
      return String(variables[key]);
    });
  } catch {
    return tmpl.replace(/\$(\w+)|\$\{(\w+)\}/g, (_, a, b) => {
      const key = a || b;
      return Object.prototype.hasOwnProperty.call(variables, key) ? String(variables[key]) : `$${key}`;
    });
  }
}

function executeCommand(command) {
  try {
    const stdout = execSync(command, {
      encoding: "utf8",
      shell: true,
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { returncode: 0, stderr: "", stdout };
  } catch (e) {
    return { returncode: e.status ?? 1, stderr: String(e.stderr ?? e.message ?? ""), stdout: "" };
  }
}

const server = new Server(
  { name: "injection-attacks-service-9", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "process_file",
    description: "Process file with custom script using templated commands.",
    inputSchema: {
      type: "object",
      properties: {
        filepath: { type: "string" },
        processor: { type: "string", default: "cat" },
        template_name: { type: "string", default: "process" },
        output_file: { type: "string", default: "" },
        options: { type: "string", default: "" },
        extra_args: { type: "string", default: "" },
      },
      required: ["filepath"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments ?? {};
  const filepath = String(args.filepath ?? "");
  const processor = String(args.processor ?? "cat");
  const templateName = String(args.template_name ?? "process");
  const outputFile = String(args.output_file ?? "");
  const options = String(args.options ?? "");
  const extraArgs = String(args.extra_args ?? "");

  const variables = {
    input_file: filepath,
    output_file: outputFile || `${filepath}.processed`,
    processor,
    command: processor,
    options,
    flags: options,
    extra_args: extraArgs,
    format: "json",
    analyzer: processor,
  };

  const command = buildCommand(templateName, variables);
  const result = executeCommand(command);

  if (result.returncode === 0) {
    return { content: [{ type: "text", text: `Processing complete. Command executed: ${command.slice(0, 100)}...` }] };
  }
  const errSnippet = String(result.stderr).slice(0, 200);
  return { content: [{ type: "text", text: `Processing failed: ${errSnippet}` }] };
});
