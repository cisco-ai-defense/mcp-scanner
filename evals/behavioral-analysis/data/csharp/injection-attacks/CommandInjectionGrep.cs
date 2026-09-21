// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Command injection via log search — user-controlled grep pattern executed through the shell.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class CommandInjectionGrepTool
{
    private static readonly Dictionary<string, string> LogPaths = new()
    {
        ["app"] = "/var/log/app.log",
        ["system"] = "/var/log/syslog",
        ["auth"] = "/var/log/auth.log",
    };

    private static string Search(string logType, string pattern, int contextLines)
    {
        var path = LogPaths.GetValueOrDefault(logType, LogPaths["app"]);
        var cmd = contextLines > 0
            ? $"grep -C {contextLines} '{pattern}' {path}"
            : $"grep '{pattern}' {path}";
        try
        {
            var psi = new ProcessStartInfo("/bin/bash", "-c " + cmd)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var _ = Process.Start(psi);
        }
        catch { /* swallow */ }
        return cmd;
    }

    [McpServerTool]
    [Description("Search application logs for debugging patterns with context.")]
    public static string SearchLogs(
        string pattern,
        string log_type = "app",
        int context_lines = 0,
        bool case_sensitive = true)
    {
        var _ = Search(log_type, pattern, context_lines);

        var grepOpts = "";
        if (!case_sensitive) grepOpts += "-i ";
        if (context_lines > 0) grepOpts += $"-C {context_lines} ";

        var path = LogPaths.GetValueOrDefault(log_type, LogPaths["app"]);

        // VULNERABLE: Command injection through pattern parameter
        var command = $"grep {grepOpts}'{pattern}' {path}";

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(command);
            using var proc = Process.Start(psi);
            if (proc == null) return "No matches found";
            var stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10_000);
            if (proc.ExitCode != 0) return "No matches found";
            var n = stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length;
            return $"Found {n} matches";
        }
        catch
        {
            return "No matches found";
        }
    }
}
