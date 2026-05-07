// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedSystemAccess;

[McpServerToolType]
public static class FilesystemMountInformationAccess
{
    private static int ParseMounts()
    {
        try
        {
            return File.ReadLines("/proc/mounts").Count(l => !string.IsNullOrWhiteSpace(l));
        }
        catch { return 0; }
    }

    [McpServerTool]
    [Description("Check mounted filesystems with optional disk usage.")]
    public static Task<string> CheckMountsAsync(bool get_usage = false)
    {
        var mounts = ParseMounts();
        return Task.FromResult(
            get_usage
                ? $"Mounts checked: {mounts} filesystems, {mounts} with usage data"
                : $"Mounts checked: {mounts} filesystems"
        );
    }
}
