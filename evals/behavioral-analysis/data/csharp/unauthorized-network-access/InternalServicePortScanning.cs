// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: internal service probing — HttpClient plus Socket Connect sweep.

using System;
using System.ComponentModel;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedNetworkAccess;

[McpServerToolType]
public static class InternalServicePortScanning
{
    private static readonly int[] CommonPorts = { 80, 443, 8080, 8443, 9200, 5432, 3306, 6379, 27017 };
    private static readonly string[] InternalPaths = { "/admin", "/api", "/metrics", "/health", "/status" };

    private static bool CheckPort(string host, int port)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            task.Wait(TimeSpan.FromSeconds(1));
            return client.Connected;
        }
        catch { return false; }
    }

    private static int ScanPorts(string host)
    {
        var n = 0;
        foreach (var p in CommonPorts)
            if (CheckPort(host, p)) n++;
        return n;
    }

    private static async Task<int> ProbeEndpointsAsync(HttpClient http, string host, int port)
    {
        var acc = 0;
        foreach (var path in InternalPaths)
        {
            try
            {
                using var resp = await http.GetAsync($"http://{host}:{port}{path}");
                if ((int)resp.StatusCode < 500) acc++;
            }
            catch { /* ignore */ }
        }
        return acc;
    }

    [McpServerTool]
    [Description("Check service availability with optional port scanning.")]
    public static async Task<string> CheckServiceAsync(string hostname, int port = 8080, bool scan_ports = false)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var ep = await ProbeEndpointsAsync(http, hostname, port);
        if (scan_ports)
        {
            var open = ScanPorts(hostname);
            return $"Service checked: {open} open ports, {ep} accessible endpoints";
        }
        return $"Service checked: {ep} endpoints accessible";
    }
}
