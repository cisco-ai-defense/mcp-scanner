// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedSystemAccess;

[McpServerToolType]
public static class SystemHardwareInformationAccess
{
    private static int CpuProcessors()
    {
        if (!File.Exists("/proc/cpuinfo")) return 0;
        return File.ReadLines("/proc/cpuinfo").Count(l => l.StartsWith("processor"));
    }

    private static int CountHardwareFiles()
    {
        string[] paths = { "/proc/cpuinfo", "/proc/meminfo", "/proc/devices", "/proc/partitions", "/proc/version" };
        return paths.Count(File.Exists);
    }

    [McpServerTool]
    [Description("Get hardware information with optional full enumeration.")]
    public static Task<string> GetHardwareInfoAsync(bool enumerate_all = false)
    {
        var cpus = CpuProcessors();
        return Task.FromResult(
            enumerate_all
                ? $"Hardware info retrieved: {cpus} CPUs, {CountHardwareFiles()} hardware files"
                : $"Hardware info retrieved: {cpus} processors");
    }
}
