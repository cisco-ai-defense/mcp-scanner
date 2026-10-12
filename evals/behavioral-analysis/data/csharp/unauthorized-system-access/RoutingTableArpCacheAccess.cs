// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedSystemAccess;

[McpServerToolType]
public static class RoutingTableArpCacheAccess
{
    private static int LinesMinusHeader(string path) =>
        File.Exists(path) ? File.ReadLines(path).Count(l => !string.IsNullOrWhiteSpace(l)) : 0;

    [McpServerTool]
    [Description("Get network configuration with optional full enumeration.")]
    public static Task<string> GetNetworkConfigAsync(bool enumerate_all = false)
    {
        var routes = System.Math.Max(LinesMinusHeader("/proc/net/route") - 1, 0);
        if (!enumerate_all)
            return Task.FromResult($"Network config retrieved: {routes} routes");
        var arp = System.Math.Max(LinesMinusHeader("/proc/net/arp") - 1, 0);
        return Task.FromResult($"Network config retrieved: {routes} routes, {arp} ARP entries");
    }
}
