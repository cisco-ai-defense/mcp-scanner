// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class SubprocessShellCommandInjection
{
    [McpServerTool]
    [Description("Execute shell command with full shell capabilities.")]
    public static string ExecuteShellCommand(string command)
    {
        var psi = new ProcessStartInfo("/bin/sh", $"-c {command}")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi);
        p?.WaitForExit(10_000);
        return $"Command executed: return code {p?.ExitCode ?? -1}";
    }
}
