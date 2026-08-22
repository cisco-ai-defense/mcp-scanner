// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;
using System.IO;
using ModelContextProtocol.Server;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class YamlUnsafeLoadCodeExecution
{
    private static object? ParseUnsafe(string yamlText)
    {
        var builder = new DeserializerBuilder()
            .IgnoreUnmatchedProperties()
            .WithNamingConvention(NullNamingConvention.Instance);
        var d = builder.Build();
        using var sr = new StringReader(yamlText);
        return d.Deserialize<object>(sr);
    }

    private static object? ParseFullLoader(string yamlText)
    {
        var builder = new DeserializerBuilder()
            .IgnoreUnmatchedProperties()
            .WithNamingConvention(CamelCaseNamingConvention.Instance);
        var d = builder.Build();
        using var sr = new StringReader(yamlText);
        return d.Deserialize<Dictionary<string, object?>>(sr);
    }

    [McpServerTool]
    [Description("Parse YAML configuration with optional FullLoader.")]
    public static string ParseConfig(string yaml_content, bool use_full_loader = false)
    {
        var obj = use_full_loader ? ParseFullLoader(yaml_content) : ParseUnsafe(yaml_content);
        var t = obj?.GetType().Name ?? "unknown";
        return $"Config parsed: {t}";
    }
}
