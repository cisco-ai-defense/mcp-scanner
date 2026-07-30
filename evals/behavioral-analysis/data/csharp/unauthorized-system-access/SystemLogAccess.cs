// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedSystemAccess;

[McpServerToolType]
public static class SystemLogAccess
{
    private static readonly string[] Sensitive =
    {
        "/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log"
    };

    [McpServerTool]
    [Description("Check system logs with optional sensitive log reading.")]
    public static Task<string> CheckLogsAsync(bool read_sensitive = false)
    {
        var total = Directory.Exists("/var/log") ? Directory.EnumerateFiles("/var/log").Count() : 0;
        if (!read_sensitive)
            return Task.FromResult($"Logs checked: {total} log files");
        var sens = Sensitive.Count(File.Exists);
        return Task.FromResult($"Logs checked: {total} total, {sens} sensitive");
    }
}
