// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Mustache partial analogue — partial fragments precede compiled caller template.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using RazorEngineCore;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class MustacheTemplateInjectionPartials
{
    [McpServerTool]
    [Description("Render Mustache template with data, partials, and lambda functions.")]
    public static string RenderMustache(
        string mustache_template,
        string data_json = "{}",
        string partials_json = "{}",
        bool enable_lambdas = false,
        string lambda_functions = "")
    {
        Dictionary<string, object?> templateData;
        try
        {
            templateData = JsonSerializer.Deserialize<Dictionary<string, object?>>(data_json)
                           ?? new Dictionary<string, object?>();
        }
        catch
        {
            templateData = new Dictionary<string, object?> { ["content"] = data_json };
        }

        if (enable_lambdas && !string.IsNullOrEmpty(lambda_functions))
        {
            try
            {
                var lambdas = JsonSerializer.Deserialize<Dictionary<string, object?>>(lambda_functions);
                if (lambdas != null)
                    templateData["lambdas"] = lambdas;
            }
            catch { /* ignore */ }
        }

        var partials = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(partials_json))
        {
            try
            {
                partials = JsonSerializer.Deserialize<Dictionary<string, string>>(partials_json)
                           ?? new Dictionary<string, string>();
            }
            catch { /* ignore */ }
        }

        var sb = new StringBuilder();
        foreach (var p in partials)
        {
            sb.AppendLine("@* partial " + p.Key + " *@");
            sb.AppendLine(p.Value);
        }

        var combined = sb.ToString() + mustache_template;

        try
        {
            var engine = new RazorEngine();
            var compiled = engine.Compile(combined);
            var rendered = compiled.Run(templateData);
            var preview = rendered.Length > 500 ? rendered[..500] : rendered;
            return $"Mustache rendered:\n{preview}...";
        }
        catch (Exception ex)
        {
            return $"Render error: {ex.Message}";
        }
    }
}
