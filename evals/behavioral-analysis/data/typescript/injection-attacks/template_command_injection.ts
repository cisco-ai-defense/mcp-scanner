// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Template / command substitution — Python string.Template analogue feeding shell:true exec.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "node:child_process";

interface ProcessFileArgs {
  filepath: string;
  processor?: string;
  template_name?: string;
  output_file?: string;
  options?: string;
  extra_args?: string;
}

const SCRIPT_TEMPLATES: Record<string, string> = {
  convert: "convert $input_file $options $output_file",
  process: "$processor -i $input_file -o $output_file $flags",
  analyze: "$analyzer --input=$input_file --format=$format $extra_args",
  custom: "$command",
};

function buildCommand(templateName: string, variables: Record<string, string>): string {
  const tmpl = SCRIPT_TEMPLATES[templateName] ?? SCRIPT_TEMPLATES.custom!;

  try {
    return tmpl.replace(/\$(\w+)|\$\{(\w+)\}/g, (_, a: string, b: string) => {
      const key = a || b!;
      if (!Object.prototype.hasOwnProperty.call(variables, key)) throw new Error("KeyError");
      return variables[key]!;
    });
  } catch {
    return tmpl.replace(/\$(\w+)|\$\{(\w+)\}/g, (_, a: string, b: string) => {
      const key = a || b!;
      return Object.prototype.hasOwnProperty.call(variables, key) ? variables[key]! : `$${key}`;
    });
  }
}

function executeCommand(command: string): { stdout: string; stderr: string; returncode: number } {
  try {
    const stdout = execSync(command, {
      encoding: "utf8",
      shell: true,
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    }) as string;
    return { returncode: 0, stderr: "", stdout };
  } catch (e: unknown) {
    const er = e as { status?: number; stderr?: Buffer; message?: string };
    return {
      returncode: er.status ?? 1,
      stderr: String(er.stderr ?? er.message ?? ""),
      stdout: "",
    };
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
  const a = req.params.arguments as ProcessFileArgs;
  const filepath = String(a.filepath ?? "");
  const processor = a.processor ?? "cat";
  const templateName = a.template_name ?? "process";
  const outputFile = a.output_file ?? "";

  const variables: Record<string, string> = {
    input_file: filepath,
    output_file: outputFile || `${filepath}.processed`,
    processor,
    command: processor,
    options: a.options ?? "",
    flags: a.options ?? "",
    extra_args: a.extra_args ?? "",
    format: "json",
    analyzer: processor,
  };

  const command = buildCommand(templateName, variables);
  const result = executeCommand(command);
  if (result.returncode === 0) {
    return { content: [{ type: "text", text: `Processing complete. Command executed: ${command.slice(0, 100)}...` }] };
  }
  return { content: [{ type: "text", text: `Processing failed: ${result.stderr.slice(0, 200)}` }] };
});
