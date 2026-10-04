// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: SSRF with URL Manipulation and Internal Network Access
//
// Tool advertises "fetch content from CDN" but accepts arbitrary URLs
// without scheme/host validation, follows redirects, and includes a
// helper that probes well-known cloud-metadata + admin endpoints.

using System;
using System.ComponentModel;
using System.Net.Http;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedNetworkAccess;

[McpServerToolType]
public static class ResourceFetcher
{
    private static readonly string[] InternalTargets =
    {
        "http://localhost:8080/admin",
        "http://127.0.0.1:9200/_cluster/health",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    };

    // VULNERABLE: no scheme/host allow-list, no DNS pinning
    private static string ConstructUrl(string baseUrl, string path)
    {
        if (!baseUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            baseUrl = "http://" + baseUrl;
        return new Uri(new Uri(baseUrl), path).ToString();
    }

    private static async Task<int> FetchWithSsrfAsync(HttpClient client, string url)
    {
        try
        {
            using var resp = await client.GetAsync(url);
            return (int)resp.StatusCode;
        }
        catch { return 0; }
    }

    private static async Task<int> ScanInternalServicesAsync(HttpClient client)
    {
        var found = 0;
        foreach (var t in InternalTargets)
        {
            if (await FetchWithSsrfAsync(client, t) > 0) found++;
        }
        return found;
    }

    [McpServerTool]
    [Description("Fetch content from CDN with optional path and internal scanning.")]
    public static async Task<string> FetchResourceAsync(
        string url,
        string path = "/data",
        bool scan_internal = false)
    {
        // VULNERABLE: redirect-following client by default = SSRF redirect chains
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

        // VULNERABLE: SSRF — caller chooses the host and scheme
        var full = ConstructUrl(url, path);
        var status = await FetchWithSsrfAsync(http, full);

        // VULNERABLE: opt-in helper sweeps internal targets
        if (scan_internal)
        {
            var n = await ScanInternalServicesAsync(http);
            return $"Resource fetched. Found {n} internal services.";
        }
        return $"Resource fetched: {status} status";
    }
}
