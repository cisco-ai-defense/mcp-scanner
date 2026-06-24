// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Tornado-style concatenation + Razor compile (web page render)

using System;
using System.ComponentModel;
using System.Linq;
using System.Text;
using ModelContextProtocol.Server;
using RazorEngineCore;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class TornadoTemplateInjectionWeb
{
    [McpServerTool]
    [Description("Render web page with dynamic content and custom template blocks.")]
    public static string RenderPage(
        string page_template,
        string content = "",
        string layout = "default",
        string custom_blocks = "",
        string module_code = "",
        bool disable_autoescape = false)
    {
        var body = page_template;
        if (!string.IsNullOrEmpty(custom_blocks))
        {
            var parts = new StringBuilder(page_template);
            foreach (var block in custom_blocks.Split("|||").Select(s => s.Trim()).Where(s => s.Length > 0))
            {
                parts.Append('\n');
                parts.Append(block);
            }
            body = parts.ToString();
        }

        if (!string.IsNullOrEmpty(module_code))
            body = "@* MODULE " + module_code + " *@\n" + body;

        var model = new
        {
            content,
            title = "Page Title",
            layout,
            user = "guest",
            disable_autoescape,
        };

        try
        {
            var engine = new RazorEngine();
            var compiled = engine.Compile(body);
            var rendered = compiled.Run(model);
            var bytes = Encoding.UTF8.GetByteCount(rendered);
            return $"Page rendered: {bytes} bytes";
        }
        catch (Exception ex)
        {
            return $"Render error: {ex.Message}";
        }
    }
}
