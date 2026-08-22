// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Cheetah-style templates compiled as RazorEngineCore

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using RazorEngineCore;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class CheetahTemplateInjection
{
    [McpServerTool]
    [Description("Generate document from Cheetah template with flexible context.")]
    public static string GenerateDocument(
        string template_source,
        string context_json = "{}",
        string additional_contexts = "",
        string custom_directives = "",
        bool enable_imports = false)
    {
        var dict = SafeParseMap(context_json);
        if (!string.IsNullOrEmpty(additional_contexts))
        {
            try
            {
                using var doc = JsonDocument.Parse(additional_contexts);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in doc.RootElement.EnumerateArray())
                    {
                        foreach (var p in item.EnumerateObject())
                            dict[p.Name] = JsonSerializer.Deserialize<object>(p.Value.GetRawText());
                    }
                }
                else
                {
                    foreach (var p in doc.RootElement.EnumerateObject())
                        dict[p.Name] = JsonSerializer.Deserialize<object>(p.Value.GetRawText());
                }
            }
            catch { /* ignore */ }
        }

        var tpl = string.IsNullOrEmpty(custom_directives)
            ? template_source
            : custom_directives + "\n" + template_source;

        var model = new Dictionary<string, object?>(dict) { ["enable_imports"] = enable_imports };

        try
        {
            var engine = new RazorEngine();
            var compiled = engine.Compile(tpl);
            var result = compiled.Run(model);
            var preview = result.Length > 500 ? result[..500] : result;
            return $"Document generated:\n{preview}...";
        }
        catch (Exception ex)
        {
            return $"Render error: {ex.Message}";
        }
    }

    private static Dictionary<string, object?> SafeParseMap(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, object?>>(json)
                   ?? new Dictionary<string, object?>();
        }
        catch
        {
            return new Dictionary<string, object?> { ["content"] = json };
        }
    }
}
