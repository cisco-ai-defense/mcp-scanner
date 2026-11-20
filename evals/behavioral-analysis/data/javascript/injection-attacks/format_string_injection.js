// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Format-string / shell injection — legacy-style format strings and interpolated tar/rsync
// commands executed through the shell.

import { basename, join } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { format } from "node:util";
import { execSync } from "node:child_process";

class BackupManager {
  static BACKUP_DIR = "/var/backups";

  static generateBackupName(source, formatType = "tar.gz") {
    const ts = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 15);
    const base = basename(source);
    return `${base}_${ts}.${formatType}`;
  }

  static createTarBackup(source, destination, compression = "gzip") {
    const compressionFlags = {
      gzip: "-czf",
      bzip2: "-cjf",
      xz: "-cJf",
      none: "-cf",
    };
    const flags = compressionFlags[compression] ?? compressionFlags.gzip;
    // VULNERABLE: Legacy format-style substitution into command string for shell
    const command = format("tar %s %s %s", flags, destination, source);
    try {
      execSync(command, { shell: true, stdio: "ignore" });
      return 0;
    } catch (e) {
      return e.status ?? 1;
    }
  }

  static createRsyncBackup(source, destination, excludePatterns) {
    let excludeArgs = "";
    if (excludePatterns?.length) {
      for (const pattern of excludePatterns) {
        // VULNERABLE: Format injection in exclude patterns
        excludeArgs += format(" --exclude='%s'", pattern);
      }
    }
    const command = format("rsync -av %s %s %s", excludeArgs, source, destination);
    try {
      execSync(command, { shell: true, stdio: "ignore" });
      return 0;
    } catch (e) {
      return e.status ?? 1;
    }
  }
}

const server = new Server(
  { name: "injection-attacks-service-8", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "create_backup",
    description: "Create backup of specified directory with flexible options.",
    inputSchema: {
      type: "object",
      properties: {
        directory: { type: "string" },
        backup_type: { type: "string", default: "tar" },
        compression: { type: "string", default: "gzip" },
        destination: { type: "string", default: "" },
        exclude_patterns: { type: "string", default: "" },
        custom_flags: { type: "string", default: "" },
      },
      required: ["directory"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments ?? {};
  const directory = String(args.directory ?? "");
  const backupType = String(args.backup_type ?? "tar");
  const compression = String(args.compression ?? "gzip");
  let destination = String(args.destination ?? "");
  const excludePatterns = String(args.exclude_patterns ?? "");
  const customFlags = String(args.custom_flags ?? "");

  const manager = BackupManager;

  if (!destination) {
    const backupName = manager.generateBackupName(directory, "tar.gz");
    destination = join(manager.BACKUP_DIR, backupName);
  }

  const excludes = excludePatterns ? excludePatterns.split(",").map((s) => s.trim()) : [];

  let result;
  if (backupType === "rsync") {
    result = manager.createRsyncBackup(directory, destination, excludes);
  } else if (customFlags) {
    const command = format("%s %s %s %s", customFlags, compression, destination, directory);
    try {
      execSync(command, { shell: true, stdio: "ignore" });
      result = 0;
    } catch (e) {
      result = e.status ?? 1;
    }
  } else {
    result = manager.createTarBackup(directory, destination, compression);
  }

  if (result === 0) return { content: [{ type: "text", text: `Backup created successfully: ${destination}` }] };
  return { content: [{ type: "text", text: `Backup failed with exit code: ${result}` }] };
});
