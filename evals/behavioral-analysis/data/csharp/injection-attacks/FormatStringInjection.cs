// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Format-style assembly of tar/rsync commands executed under /bin/bash -c.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class FormatStringInjectionTool
{
    private const string BackupDir = "/var/backups";

    private sealed class BackupManager
    {
        public static string GenerateBackupName(string source, string formatType = "tar.gz")
        {
            var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var baseName = Path.GetFileName(source);
            return $"{baseName}_{ts}.{formatType}";
        }

        public static int CreateTarBackup(string source, string destination, string compression)
        {
            var compressionFlags = new Dictionary<string, string>
            {
                ["gzip"] = "-czf",
                ["bzip2"] = "-cjf",
                ["xz"] = "-cJf",
                ["none"] = "-cf",
            };
            var flags = compressionFlags.GetValueOrDefault(compression, compressionFlags["gzip"]);
            var command = string.Format("tar {0} {1} {2}", flags, destination, source);
            return RunShell(command);
        }

        public static int CreateRsyncBackup(string source, string destination, List<string>? excludePatterns)
        {
            var excludeArgs = "";
            if (excludePatterns != null)
            {
                foreach (var pattern in excludePatterns)
                {
                    excludeArgs += string.Format(" --exclude='{0}'", pattern);
                }
            }

            var command = string.Format("rsync -av {0} {1} {2}", excludeArgs, source, destination);
            return RunShell(command);
        }
    }

    private static int RunShell(string cmd)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(cmd);
        using var p = Process.Start(psi);
        p?.WaitForExit();
        return p?.ExitCode ?? 1;
    }

    [McpServerTool]
    [Description("Create backup of specified directory with flexible options.")]
    public static string CreateBackup(
        string directory,
        string backup_type = "tar",
        string compression = "gzip",
        string destination = "",
        string exclude_patterns = "",
        string custom_flags = "")
    {
        if (string.IsNullOrEmpty(destination))
        {
            var backupName = BackupManager.GenerateBackupName(directory, "tar.gz");
            destination = Path.Combine(BackupDir, backupName);
        }

        var excludes = string.IsNullOrEmpty(exclude_patterns)
            ? []
            : exclude_patterns.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

        int result;
        if (backup_type == "rsync")
        {
            result = BackupManager.CreateRsyncBackup(directory, destination, excludes);
        }
        else if (!string.IsNullOrEmpty(custom_flags))
        {
            var command = string.Format("{0} {1} {2} {3}", custom_flags, compression, destination, directory);
            result = RunShell(command);
        }
        else
        {
            result = BackupManager.CreateTarBackup(directory, destination, compression);
        }

        return result == 0
            ? $"Backup created successfully: {destination}"
            : $"Backup failed with exit code: {result}";
    }
}
