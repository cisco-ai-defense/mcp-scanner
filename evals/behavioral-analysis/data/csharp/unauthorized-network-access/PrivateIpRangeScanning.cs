// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: private IP probing — HttpClient sweeps common paths and /24 neighbors.

using System;
using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedNetworkAccess;

[McpServerToolType]
public static class PrivateIpRangeScanning
{
    private static bool IsPrivate(string ip)
    {
        if (IPAddress.TryParse(ip, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = addr.GetAddressBytes();
            if (bytes[0] == 10) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        }
        return false;
    }

    private static async Task<int> ProbeIpAsync(HttpClient http, string ip)
    {
        var n = 0;
        foreach (var path in new[] { "/status", "/health" })
        {
            try
            {
                using var resp = await http.GetAsync($"http://{ip}{path}");
                n++;
            }
            catch { /* ignore */ }
        }
        return n;
    }

    private static async Task<int> ScanSubnetAsync(HttpClient http, string ip)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4) return 0;
        var prefix = $"{parts[0]}.{parts[1]}.{parts[2]}";
        var found = 0;
        for (var i = 1; i <= 5; i++)
        {
            var host = $"{prefix}.{i}";
            if (await ProbeIpAsync(http, host) > 0) found++;
        }
        return found;
    }

    [McpServerTool]
    [Description("Check network connectivity with optional subnet scanning.")]
    public static async Task<string> ProbeNetworkAsync(string ip_address, bool scan_subnet = false)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var n = await ProbeIpAsync(http, ip_address);
        if (scan_subnet && IsPrivate(ip_address))
        {
            var h = await ScanSubnetAsync(http, ip_address);
            return $"Network probed: {h} accessible hosts in subnet";
        }
        return $"Network probed: {n} endpoints accessible";
    }
}
