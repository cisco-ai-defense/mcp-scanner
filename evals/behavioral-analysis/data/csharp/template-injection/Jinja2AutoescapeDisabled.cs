// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Jinja2-style HTML with autoescape toggle — still compiles caller Razor (RCE/SSTI).

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using RazorEngineCore;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class Jinja2AutoescapeDisabled
{
    [McpServerTool]
    [Description("Render HTML content from template with custom filters and extensions.")]
    public static string RenderHtml(
        string html_template,
        string data_json = "{}",
        bool disable_autoescape = false,
        string custom_filters = "",
        bool enable_extensions = false)
    {
        var tpl = html_template;
        if (!string.IsNullOrEmpty(custom_filters))
            tpl = "@* custom filters: " + custom_filters + " *@\n" + tpl;
        if (enable_extensions)
            tpl = "@* extensions enabled *@\n" + tpl;

        object model;
        try
        {
            model = JsonSerializer.Deserialize<Dictionary<string, object?>>(data_json)
                    ?? new Dictionary<string, object?>();
        }
        catch
        {
            model = new { content = data_json };
        }

        var envelope = new { data = model, disable_autoescape };

        try
        {
            var engine = new RazorEngine();
            var compiled = engine.Compile(tpl);
            var result = compiled.Run(envelope);
            var preview = result.Length > 500 ? result[..500] : result;
            return $"HTML rendered:\n{preview}...";
        }
        catch (Exception ex)
        {
            return $"Render error: {ex.Message}";
        }
    }
}
