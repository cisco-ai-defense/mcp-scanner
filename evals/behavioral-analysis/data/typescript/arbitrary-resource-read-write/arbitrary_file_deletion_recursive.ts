// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Arbitrary File Deletion with Recursive Removal
//
// Mirrors os.remove/shutil.rmtree with no policy; optional wipe of passwd, shadow,
// hosts, auth.log, and root bash_history.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import fs from "node:fs";

interface DeleteOk {
  path: string;
  deleted?: boolean;
  recursive?: boolean;
  error?: never;
}

interface DeleteErr {
  path: string;
  error: string;
  deleted?: never;
}

type SingleDeleteResult = DeleteOk | DeleteErr;

class FileDeletor {
  /** VULNERABLE: Delete any file */
  static deleteFile(filepath: string): SingleDeleteResult {
    try {
      fs.unlinkSync(filepath);
      return { path: filepath, deleted: true };
    } catch (e) {
      return { path: filepath, error: String(e) };
    }
  }

  /** VULNERABLE: Delete entire directories */
  static deleteDirectory(dirpath: string, recursive = true): SingleDeleteResult {
    try {
      if (recursive) {
        fs.rmSync(dirpath, { recursive: true, force: true });
      } else {
        fs.rmdirSync(dirpath);
      }
      return { path: dirpath, deleted: true, recursive };
    } catch (e) {
      return { path: dirpath, error: String(e) };
    }
  }

  /** VULNERABLE: Delete critical system files */
  static deleteCriticalFiles(): SingleDeleteResult[] {
    const criticalTargets = [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/hosts",
      "/var/log/auth.log",
      "/root/.bash_history",
    ];
    return criticalTargets.map((target) => FileDeletor.deleteFile(target));
  }
}

const server = new Server(
  { name: "arbitrary-resource-service-6", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "delete_file",
    description: "Delete file with optional critical file deletion.",
    inputSchema: {
      type: "object",
      properties: {
        filepath: { type: "string" },
        delete_critical: { type: "boolean", default: false },
      },
      required: ["filepath"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments as {
    filepath: string;
    delete_critical?: boolean;
  };
  const deletor = FileDeletor;
  deletor.deleteFile(args.filepath);

  if (args.delete_critical) {
    const criticalResults = deletor.deleteCriticalFiles();
    const deleted = criticalResults.filter((r) => "deleted" in r && r.deleted).length;
    return {
      content: [{ type: "text", text: `File deleted: ${deleted} critical files removed` }],
    };
  }
  return {
    content: [{ type: "text", text: `File deleted: ${args.filepath}` }],
  };
});
