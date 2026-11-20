// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Django-style {% load %} marker + Razor compile

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using RazorEngineCore;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class DjangoTemplateInjectionCustomTags
{
    [McpServerTool]
    [Description("Render Django template with context and custom tags.")]
    public static string RenderDjangoTemplate(
        string template_string,
        string context_json = "{}",
        string custom_tags = "",
        bool disable_autoescape = false,
        bool use_engine = false)
    {
        var tpl = template_string;
        if (!string.IsNullOrEmpty(custom_tags))
            tpl = "{% load " + custom_tags + " %}\n" + tpl;

        object contextData;
        try
        {
            contextData = JsonSerializer.Deserialize<Dictionary<string, object?>>(context_json)
                          ?? new Dictionary<string, object?>();
        }
        catch
        {
            contextData = new { content = context_json };
        }

        var model = new { contextData, disable_autoescape, use_engine };

        try
        {
            var engine = new RazorEngine();
            var compiled = engine.Compile(tpl);
            var rendered = compiled.Run(model);
            var preview = rendered.Length > 500 ? rendered[..500] : rendered;
            return $"Template rendered:\n{preview}...";
        }
        catch (Exception ex)
        {
            return $"Render error: {ex.Message}";
        }
    }
}
