// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: OS command injection — compression paths and archive names are interpolated into
// shell commands executed via child_process / system-style exec.

import { existsSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "node:child_process";

class FileCompressor {
  static COMPRESSION_TYPES = {
    gzip: "gzip -f",
    bzip2: "bzip2 -f",
    xz: "xz -f",
    zip: "zip -r",
  };

  static compress(filename, compressionType = "gzip", outputName) {
    const cmdBase = FileCompressor.COMPRESSION_TYPES[compressionType] ?? FileCompressor.COMPRESSION_TYPES.gzip;
    let cmd;
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
    } catch (e) {
      return e.status ?? 1;
    }
  }

  static compressDirectory(directory, archiveName, compressionType = "gzip") {
    let cmd;
    if (compressionType === "zip") {
      cmd = `zip -r ${archiveName} ${directory}`;
    } else {
      cmd = `tar -czf ${archiveName} ${directory}`;
    }
    try {
      execSync(cmd, { shell: true, stdio: "ignore" });
      return 0;
    } catch (e) {
      return e.status ?? 1;
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
  const args = req.params.arguments ?? {};
  const filename = String(args.filename ?? "");
  const compressionType = String(args.compression_type ?? "gzip");
  const outputName = String(args.output_name ?? "");
  const compressDirectory = Boolean(args.compress_directory);
  const _preserve = args.preserve_original !== false;

  const compressor = FileCompressor;

  if (!compressDirectory && !existsSync(filename)) {
    return { content: [{ type: "text", text: `File not found: ${filename}` }] };
  }

  let result;
  if (compressDirectory) {
    let out = outputName;
    if (!out) out = `${filename}.tar.gz`;
    result = compressor.compressDirectory(filename, out, compressionType);
  } else {
    result = compressor.compress(filename, compressionType, outputName || undefined);
  }

  if (result === 0) {
    return { content: [{ type: "text", text: `Compression successful: ${filename}` }] };
  }
  return { content: [{ type: "text", text: `Compression failed with code: ${result}` }] };
});
