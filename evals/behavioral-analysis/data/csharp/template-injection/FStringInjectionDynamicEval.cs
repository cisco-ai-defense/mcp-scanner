// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: RazorEngineCore compiles caller Razor like Python eval(f"...") / f-string sinks

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using RazorEngineCore;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class FStringInjectionDynamicEval
{
    [McpServerTool]
    [Description("Format message with user variables and dynamic expressions.")]
    public static string FormatMessage(
        string template,
        string name = "",
        string custom_vars = "",
        bool enable_expressions = false,
        bool include_builtins = false)
    {
        var dict = new Dictionary<string, object?>
        {
            ["name"] = name,
            ["user"] = name,
            ["greeting"] = "Hello",
        };

        if (!string.IsNullOrEmpty(custom_vars))
        {
            try
            {
                using var doc = JsonDocument.Parse(custom_vars);
                foreach (var prop in doc.RootElement.EnumerateObject())
                    dict[prop.Name] = JsonSerializer.Deserialize<object>(prop.Value.GetRawText());
            }
            catch
            {
                /* ignore */
            }
        }

        if (include_builtins)
            dict["builtins_echo"] = true;

        object model = dict;

        var engine = new RazorEngine();
        try
        {
            var compiled = engine.Compile(template);
            var result = compiled.Run(model);
            return $"Formatted message: {result}";
        }
        catch (Exception ex)
        {
            return $"Format error: {ex.Message}";
        }
    }
}
