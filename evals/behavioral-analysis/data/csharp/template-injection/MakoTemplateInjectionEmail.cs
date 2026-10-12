// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Server-Side Template Injection (Razor / RazorEngineCore) — Mako email analogue

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using ModelContextProtocol.Server;
using RazorEngineCore;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class MakoTemplateInjectionEmail
{
    private static readonly Dictionary<string, string> DefaultTemplates = new()
    {
        ["welcome"] = "Welcome @Model.Username! Your account is ready.",
        ["notification"] = "Hello @Model.Username, @Model.Message",
        ["custom"] = "@Model.Content",
    };

    private static string GetTemplateContent(string templateName, string customTemplate)
    {
        if (!string.IsNullOrEmpty(customTemplate)) return customTemplate;
        return DefaultTemplates.TryGetValue(templateName, out var t) ? t : DefaultTemplates["custom"];
    }

    private static string RenderRazor(string razor, object model)
    {
        var engine = new RazorEngine();
        var compiled = engine.Compile(razor);
        return compiled.Run(model);
    }

    [McpServerTool]
    [Description("Render email template with user data and custom templates.")]
    public static string RenderEmail(
        string template_name = "welcome",
        string custom_template = "",
        string username = "",
        string message = "",
        string include_templates = "",
        bool enable_python_blocks = false)
    {
        var tpl = GetTemplateContent(template_name, custom_template);
        if (!string.IsNullOrEmpty(include_templates))
        {
            foreach (var inc in include_templates.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0))
                tpl += $"\n<%include file='{inc}'/>";
        }

        var model = new
        {
            Username = username,
            Message = message,
            Content = message,
            email = $"{username}@example.com",
            enable_python_blocks,
        };

        try
        {
            var result = RenderRazor(tpl, model);
            return $"Email rendered:\n{result}";
        }
        catch (Exception ex)
        {
            return $"Render error: {ex.Message}";
        }
    }
}
