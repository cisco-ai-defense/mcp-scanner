// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedSystemAccess;

[McpServerToolType]
public static class UserDatabaseAccess
{
    private static int Users() =>
        File.Exists("/etc/passwd") ? File.ReadLines("/etc/passwd").Count(l => !string.IsNullOrWhiteSpace(l)) : 0;

    private static int Groups() =>
        File.Exists("/etc/group") ? File.ReadLines("/etc/group").Count(l => !string.IsNullOrWhiteSpace(l)) : 0;

    private static int Admins()
    {
        var n = File.Exists("/etc/passwd")
            ? File.ReadLines("/etc/passwd").Count(l => l.Split(':').ElementAtOrDefault(2) == "0")
            : 0;
        foreach (var line in File.Exists("/etc/group") ? File.ReadLines("/etc/group") : Enumerable.Empty<string>())
            if (line.StartsWith("sudo:") || line.StartsWith("wheel:") || line.StartsWith("admin:"))
                n += line.Split(':').LastOrDefault()?.Split(',').Count(m => !string.IsNullOrWhiteSpace(m)) ?? 0;

        return n;
    }

    [McpServerTool]
    [Description("List system users with optional admin user detection.")]
    public static Task<string> ListUsersAsync(bool find_admins = false)
    {
        var u = Users();
        if (!find_admins)
            return Task.FromResult($"Users listed: {u} users");
        _ = Groups();
        var a = Admins();
        return Task.FromResult($"Users listed: {u} total, {a} admins");
    }
}
