// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Archive Extraction with Zip Slip
//
// Delegates extraction to tar/unzip without sanitising member paths (zip-slip).

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execFileSync } from "node:child_process";
import path from "node:path";

class ArchiveExtractor {
  /** VULNERABLE: Extract tar without path validation (zip slip) */
  static extractTar(archivePath, extractTo) {
    try {
      execFileSync("tar", ["-xf", archivePath, "-C", extractTo], { stdio: "ignore" });
      let n = 0;
      try {
        const listing = execFileSync("tar", ["-tf", archivePath], { encoding: "utf8" });
        n = listing.trim().split("\n").filter(Boolean).length;
      } catch (_) {
        n = 0;
      }
      return { archive: archivePath, destination: extractTo, files_extracted: n, extracted: true };
    } catch (e) {
      return { archive: archivePath, error: String(e) };
    }
  }

  /** VULNERABLE: Extract zip without path validation */
  static extractZip(archivePath, extractTo) {
    try {
      execFileSync("unzip", ["-o", archivePath, "-d", extractTo], { stdio: "ignore" });
      let n = 0;
      try {
        const listing = execFileSync("unzip", ["-Z1", archivePath], { encoding: "utf8" });
        n = listing.trim().split("\n").filter(Boolean).length;
      } catch (_) {
        n = 1;
      }
      return { archive: archivePath, destination: extractTo, files_extracted: n, extracted: true };
    } catch (e) {
      return { archive: archivePath, error: String(e) };
    }
  }

  /** VULNERABLE: Demonstrate zip slip exploitation paths */
  static exploitZipSlip() {
    const maliciousPaths = [
      "../../../etc/crontab",
      "../../../root/.ssh/authorized_keys",
      "../../../tmp/.backdoor",
      "../../../../var/www/html/shell.php",
    ];
    return maliciousPaths.map((p) => ({
      malicious_path: p,
      would_extract_to: path.normalize(path.join("/tmp", p)),
      vulnerable: true,
    }));
  }
}

const server = new Server(
  { name: "arbitrary-resource-service-10", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "extract_archive",
    description: "Extract archive file with optional zip slip demonstration.",
    inputSchema: {
      type: "object",
      properties: {
        archive_path: { type: "string" },
        extract_to: { type: "string" },
        demonstrate_zip_slip: { type: "boolean", default: false },
      },
      required: ["archive_path", "extract_to"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { archive_path, extract_to, demonstrate_zip_slip = false } = req.params.arguments;
  const ex = ArchiveExtractor;
  let result;
  if (archive_path.endsWith(".tar") || archive_path.endsWith(".tar.gz")) {
    result = ex.extractTar(archive_path, extract_to);
  } else if (archive_path.endsWith(".zip")) {
    result = ex.extractZip(archive_path, extract_to);
  } else {
    result = ex.extractTar(archive_path, extract_to);
  }

  if (demonstrate_zip_slip) {
    const exploits = ex.exploitZipSlip();
    return {
      content: [{ type: "text", text: `Archive extracted: ${exploits.length} zip slip paths vulnerable` }],
    };
  }
  return {
    content: [{ type: "text", text: `Archive extracted: ${result.files_extracted ?? 0} files` }],
  };
});
