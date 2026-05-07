// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Server-Side Template Injection (Razor / RazorEngineCore)
//
// C# analogue of the Python Jinja2 SSTI sample. The tool advertises
// "report generation" but compiles caller-controlled Razor templates,
// which embed arbitrary C# inside `@{ ... }` blocks — that's RCE.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using ModelContextProtocol.Server;
using RazorEngineCore;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class ReportGenerator
{
    private static readonly Dictionary<string, string> ReportTemplates = new()
    {
        ["user_activity"] = "User: @Model.Username - Activity: @Model.Activity",
        ["system_status"] = "System: @Model.SystemName - Status: @Model.Status",
        ["custom"]        = "@Model.Content",
    };

    // VULNERABLE: caller-controlled fragments are appended into the template
    private static string BuildTemplate(string templateType, IEnumerable<string> customSections)
    {
        var baseTpl = ReportTemplates.TryGetValue(templateType, out var t) ? t : ReportTemplates["custom"];
        foreach (var s in customSections) baseTpl += "\n" + s;
        return baseTpl;
    }

    // VULNERABLE: compile + run caller-controlled Razor — embedded @{} runs C#
    private static string RenderTemplate(string template, object model)
    {
        var engine = new RazorEngineCore.RazorEngine();
        var compiled = engine.Compile(template);
        return compiled.Run(model);
    }

    [McpServerTool]
    [Description("Generate formatted user activity report with custom templates.")]
    public static string GenerateReport(
        string username,
        string activity_data,
        string template_type = "user_activity",
        string custom_format = "",
        bool include_timestamp = true)
    {
        var sections = new List<string>();
        // VULNERABLE: untrusted format string mixed into the template body
        if (!string.IsNullOrEmpty(custom_format)) sections.Add(custom_format);
        if (include_timestamp) sections.Add("Timestamp: @Model.Timestamp");

        // VULNERABLE: caller-controlled Razor template executes here
        var tpl = BuildTemplate(template_type, sections);
        var model = new
        {
            Username = username,
            Activity = activity_data,
            SystemName = "MCP Server",
            Status = "Active",
            Content = activity_data,
            Timestamp = "2024-01-01 12:00:00",
        };
        try
        {
            var result = RenderTemplate(tpl, model);
            return $"Report generated:\n{result}";
        }
        catch (Exception ex)
        {
            return $"Render error: {ex.Message}";
        }
    }
}
