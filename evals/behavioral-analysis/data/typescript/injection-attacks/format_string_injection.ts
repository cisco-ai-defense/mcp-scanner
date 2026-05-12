// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Format-string / shell injection — util.format-style strings combined with tar/rsync under shell exec.

import { basename, join } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { format } from "node:util";
import { execSync } from "node:child_process";

interface CreateBackupArgs {
  directory: string;
  backup_type?: string;
  compression?: string;
  destination?: string;
  exclude_patterns?: string;
  custom_flags?: string;
}

class BackupManager {
  static readonly BACKUP_DIR = "/var/backups";

  static generateBackupName(source: string, formatType = "tar.gz"): string {
    const ts = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 15);
    const base = basename(source);
    return `${base}_${ts}.${formatType}`;
  }

  static createTarBackup(source: string, destination: string, compression = "gzip"): number {
    const compressionFlags: Record<string, string> = {
      gzip: "-czf",
      bzip2: "-cjf",
      xz: "-cJf",
      none: "-cf",
    };
    const flags = compressionFlags[compression] ?? compressionFlags.gzip!;
    const command = format("tar %s %s %s", flags, destination, source);
    try {
      execSync(command, { shell: true, stdio: "ignore" });
      return 0;
    } catch (e: unknown) {
      const status = typeof e === "object" && e !== null && "status" in e ? Number((e as { status?: number }).status) : 1;
      return status;
    }
  }

  static createRsyncBackup(source: string, destination: string, excludePatterns?: string[]): number {
    let excludeArgs = "";
    if (excludePatterns?.length) {
      for (const pattern of excludePatterns) {
        excludeArgs += format(" --exclude='%s'", pattern);
      }
    }
    const command = format("rsync -av %s %s %s", excludeArgs, source, destination);
    try {
      execSync(command, { shell: true, stdio: "ignore" });
      return 0;
    } catch (e: unknown) {
      const status = typeof e === "object" && e !== null && "status" in e ? Number((e as { status?: number }).status) : 1;
      return status;
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
  const a = req.params.arguments as CreateBackupArgs;
  const directory = String(a.directory ?? "");
  const backupType = a.backup_type ?? "tar";
  const compression = a.compression ?? "gzip";
  let destination = a.destination ?? "";
  const excludesList = (a.exclude_patterns ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const customFlags = a.custom_flags ?? "";

  let destResolved = destination;
  if (!destResolved) {
    const backupName = BackupManager.generateBackupName(directory, "tar.gz");
    destResolved = join(BackupManager.BACKUP_DIR, backupName);
  }

  let result: number;
  if (backupType === "rsync") {
    result = BackupManager.createRsyncBackup(directory, destResolved, excludesList);
  } else if (customFlags) {
    const command = format("%s %s %s %s", customFlags, compression, destResolved, directory);
    try {
      execSync(command, { shell: true, stdio: "ignore" });
      result = 0;
    } catch (e: unknown) {
      result = typeof e === "object" && e !== null && "status" in e ? Number((e as { status?: number }).status) : 1;
    }
  } else {
    result = BackupManager.createTarBackup(directory, destResolved, compression);
  }

  if (result === 0) return { content: [{ type: "text", text: `Backup created successfully: ${destResolved}` }] };
  return { content: [{ type: "text", text: `Backup failed with exit code: ${result}` }] };
});
