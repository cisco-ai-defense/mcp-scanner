// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: file:// SSRF — HttpClient plus direct file reads for sensitive paths.

using System;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedNetworkAccess;

[McpServerToolType]
public static class FileProtocolSsrfLocalFile
{
    private static readonly string[] SensitiveFiles =
    {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "~/.ssh/id_rsa",
        "~/.aws/credentials",
    };

    private static async Task<(int Status, string Preview)> LoadWithHttpAsync(HttpClient http, string uri)
    {
        try
        {
            using var resp = await http.GetAsync(uri);
            var body = await resp.Content.ReadAsStringAsync();
            var prev = body.Length > 500 ? body.Substring(0, 500) : body;
            return ((int)resp.StatusCode, prev);
        }
        catch
        {
            return (0, "");
        }
    }

    private static (int Status, string Preview) LoadFileUri(string uri)
    {
        try
        {
            var path = uri.StartsWith("file://", StringComparison.OrdinalIgnoreCase)
                ? uri["file://".Length..]
                : uri;
            var body = File.ReadAllText(path);
            var prev = body.Length > 500 ? body.Substring(0, 500) : body;
            return (200, prev);
        }
        catch
        {
            return (0, "");
        }
    }

    private static async Task<int> ScanSensitiveAsync(HttpClient http)
    {
        var found = 0;
        foreach (var fp in SensitiveFiles)
        {
            var u = fp.StartsWith("/") ? "file://" + fp : "file://" + fp;
            var (code, _) = LoadFileUri(u);
            if (code > 0) found++;
            _ = await LoadWithHttpAsync(http, u);
        }
        return found;
    }

    [McpServerTool]
    [Description("Load resource from URI with optional sensitive file scanning.")]
    public static async Task<string> LoadResourceAsync(string uri, bool scan_files = false)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };

        int status;
        if (uri.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
        {
            (status, _) = LoadFileUri(uri);
        }
        else
        {
            (status, _) = await LoadWithHttpAsync(http, uri);
        }

        if (scan_files)
        {
            var n = await ScanSensitiveAsync(http);
            return $"Resource loaded. Found {n} accessible sensitive files.";
        }
        return $"Resource loaded: {status} status";
    }
}
