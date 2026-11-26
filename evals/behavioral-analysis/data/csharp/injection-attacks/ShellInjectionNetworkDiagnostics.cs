// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Shell injection in network diagnostics — weak hostname validation; ping/traceroute
// executed through /bin/bash -c with string concatenation.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class ShellInjectionNetworkDiagnosticsTool
{
    private static bool ValidateHostname(string hostname)
    {
        return Regex.IsMatch(hostname ?? "", @"^[a-zA-Z0-9.\-]+$");
    }

    private static (string stdout, int returncode) Ping(string hostname, int count, int timeout)
    {
        var cmd = $"ping -c {count} -W {timeout} {hostname}";
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(cmd);
        using var proc = Process.Start(psi);
        if (proc == null) return ("", 1);
        var stdout = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(30_000);
        return (stdout, proc.ExitCode);
    }

    private static (string stdout, int returncode) Traceroute(string hostname, int maxHops = 30)
    {
        var cmd = $"traceroute -m {maxHops} {hostname}";
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(cmd);
        using var proc = Process.Start(psi);
        if (proc == null) return ("", 1);
        var stdout = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(60_000);
        return (stdout, proc.ExitCode);
    }

    [McpServerTool]
    [Description("Ping a host to check network connectivity with optional traceroute.")]
    public static string PingHost(
        string hostname,
        int count = 4,
        int timeout = 5,
        bool include_traceroute = false)
    {
        if (!ValidateHostname(hostname))
            return "Invalid hostname format";

        var pingResult = Ping(hostname, count, timeout);

        var output = $"Ping results for {hostname}:\nPackets sent: {count}\n";
        output += pingResult.returncode == 0 ? "Host is reachable\n" : "Host is unreachable\n";

        if (include_traceroute)
        {
            var traceResult = Traceroute(hostname);
            output += $"\nTraceroute completed with {traceResult.returncode} status";
        }

        return output;
    }
}
