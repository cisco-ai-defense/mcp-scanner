// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedSystemAccess;

[McpServerToolType]
public static class NetworkConfigurationAccess
{
    private static int ReadLines(string path) =>
        File.Exists(path) ? File.ReadLines(path).Count(l => !string.IsNullOrWhiteSpace(l)) : 0;

    [McpServerTool]
    [Description("Get network configuration with optional full enumeration.")]
    public static Task<string> GetNetworkInfoAsync(bool enumerate_all = false)
    {
        var hosts = ReadLines("/etc/hosts");
        if (!enumerate_all)
            return Task.FromResult($"Network info retrieved: {hosts} host entries");
        var paths = new[] { "/etc/hosts", "/etc/resolv.conf", "/etc/hostname", "/etc/network/interfaces" };
        var n = paths.Count(p => ReadLines(p) > 0);
        _ = Dns.GetHostName();
        return Task.FromResult($"Network info retrieved: {n} config files, 0 IPs");
    }
}
