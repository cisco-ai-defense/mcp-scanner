// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: OS command injection — compression paths and archive names are interpolated into
// shell commands executed via child_process / system-style exec.

import { existsSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "node:child_process";

interface CompressFileArgs {
  filename: string;
  compression_type?: string;
  output_name?: string;
  compress_directory?: boolean;
  preserve_original?: boolean;
}

class FileCompressor {
  static readonly COMPRESSION_TYPES: Record<string, string> = {
    gzip: "gzip -f",
    bzip2: "bzip2 -f",
    xz: "xz -f",
    zip: "zip -r",
  };

  static compress(filename: string, compressionType = "gzip", outputName?: string): number {
    const cmdBase = FileCompressor.COMPRESSION_TYPES[compressionType] ?? FileCompressor.COMPRESSION_TYPES.gzip;
    let cmd: string;
    if (outputName) {
      if (compressionType === "zip") {
        cmd = `${cmdBase} ${outputName} ${filename}`;
      } else {
        cmd = `${cmdBase} -c ${filename} > ${outputName}`;
      }
    } else {
      cmd = `${cmdBase} ${filename}`;
    }
    try {
      execSync(cmd, { shell: true, stdio: "ignore" });
      return 0;
    } catch (e: unknown) {
      const status = typeof e === "object" && e !== null && "status" in e ? Number((e as { status?: number }).status) : 1;
      return status;
    }
  }

  static compressDirectory(directory: string, archiveName: string, compressionType = "gzip"): number {
    const cmd = compressionType === "zip"
      ? `zip -r ${archiveName} ${directory}`
      : `tar -czf ${archiveName} ${directory}`;
    try {
      execSync(cmd, { shell: true, stdio: "ignore" });
      return 0;
    } catch (e: unknown) {
      const status = typeof e === "object" && e !== null && "status" in e ? Number((e as { status?: number }).status) : 1;
      return status;
    }
  }
}

const server = new Server(
  { name: "injection-attacks-service-4", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "compress_file",
    description: "Compress files or directories using various compression algorithms.",
    inputSchema: {
      type: "object",
      properties: {
        filename: { type: "string" },
        compression_type: { type: "string", default: "gzip" },
        output_name: { type: "string", default: "" },
        compress_directory: { type: "boolean", default: false },
        preserve_original: { type: "boolean", default: true },
      },
      required: ["filename"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments as CompressFileArgs;
  const filename = String(a.filename ?? "");
  const compressionType = a.compression_type ?? "gzip";
  const outputName = a.output_name ?? "";
  const compressDirectory = Boolean(a.compress_directory);

  if (!compressDirectory && !existsSync(filename)) {
    return { content: [{ type: "text", text: `File not found: ${filename}` }] };
  }

  let result: number;
  if (compressDirectory) {
    const out = outputName || `${filename}.tar.gz`;
    result = FileCompressor.compressDirectory(filename, out, compressionType);
  } else {
    result = FileCompressor.compress(filename, compressionType, outputName || undefined);
  }

  if (result === 0) {
    return { content: [{ type: "text", text: `Compression successful: ${filename}` }] };
  }
  return { content: [{ type: "text", text: `Compression failed with code: ${result}` }] };
});
