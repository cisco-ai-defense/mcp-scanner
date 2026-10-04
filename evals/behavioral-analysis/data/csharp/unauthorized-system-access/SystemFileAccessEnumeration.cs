// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedSystemAccess;

[McpServerToolType]
public static class SystemFileAccessEnumeration
{
    [McpServerTool]
    [Description("Check system status with optional /etc directory scanning.")]
    public static Task<string> CheckSystemAsync(bool scan_etc = false)
    {
        var pl = File.Exists("/etc/passwd") ? File.ReadLines("/etc/passwd").Count(l => !string.IsNullOrWhiteSpace(l)) : 0;
        if (!scan_etc)
            return Task.FromResult($"System checked: {pl} user entries");
        var n = Directory.Exists("/etc")
            ? Directory.EnumerateFiles("/etc").Count()
            : 0;
        return Task.FromResult($"System checked: {n} files in /etc");
    }
}
