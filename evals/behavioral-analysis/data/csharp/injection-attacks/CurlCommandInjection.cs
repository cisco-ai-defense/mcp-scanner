// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Curl / shell injection — poorly validated URL and header strings merged into bash -c curl.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class CurlCommandInjectionTool
{
    private static bool ValidateUrl(string url)
    {
        return Regex.IsMatch(url ?? "", @"^https?://");
    }

    private static string BuildCurlCommand(
        string url,
        string method,
        IReadOnlyDictionary<string, string> headers,
        string data,
        string outputFile,
        bool followRedirects,
        string customOptions)
    {
        var cmdParts = new List<string> { "curl" };

        if (!string.Equals(method, "GET", StringComparison.Ordinal))
            cmdParts.Add($"-X {method}");

        foreach (var kv in headers)
            cmdParts.Add($"-H '{kv.Key}: {kv.Value}'");

        if (!string.IsNullOrEmpty(data))
            cmdParts.Add($"-d '{data}'");

        if (!string.IsNullOrEmpty(outputFile))
            cmdParts.Add($"-o {outputFile}");

        if (followRedirects)
            cmdParts.Add("-L");

        if (!string.IsNullOrEmpty(customOptions))
            cmdParts.Add(customOptions);

        cmdParts.Add(url);
        return string.Join(" ", cmdParts);
    }

    private static (int returncode, string stdout, string stderr) ExecuteCurl(string command)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(command);
        using var p = Process.Start(psi);
        if (p == null) return (1, "", "");
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit(30_000);
        return (p.ExitCode, stdout, stderr);
    }

    [McpServerTool]
    [Description("Fetch content from URL using curl with flexible HTTP options.")]
    public static string FetchUrl(
        string url,
        string method = "GET",
        string headers = "",
        string post_data = "",
        string output_file = "",
        string custom_options = "",
        bool follow_redirects = true)
    {
        if (!ValidateUrl(url))
            return "Invalid URL format";

        var headerDict = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(headers))
        {
            foreach (var header in headers.Split(';'))
            {
                var idx = header.IndexOf(':');
                if (idx > 0)
                {
                    var key = header[..idx].Trim();
                    headerDict[key] = header[(idx + 1)..].Trim();
                }
            }
        }

        var command = BuildCurlCommand(
            url,
            method,
            headerDict,
            post_data,
            output_file,
            follow_redirects,
            custom_options);

        var result = ExecuteCurl(command);
        if (result.returncode == 0)
        {
            if (!string.IsNullOrEmpty(output_file))
                return $"Content saved to: {output_file}";
            return $"Content fetched: {result.stdout.Length} bytes";
        }

        var err = result.stderr.Length > 200 ? result.stderr[..200] : result.stderr;
        return $"Request failed: {err}";
    }
}
