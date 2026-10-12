// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: str.format-style injection — string.Format plus naïve {token} replacement

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class FormatMethodInjectionAttributeAccess
{
    [McpServerTool]
    [Description("Format string with provided values and flexible formatting options.")]
    public static string FormatString(
        string format_str,
        string values_json = "{}",
        string positional_args = "",
        bool include_builtins = false,
        bool use_format_map = false)
    {
        if (!string.IsNullOrWhiteSpace(positional_args))
        {
            try
            {
                var args = positional_args.Split(',').Select(a => (object)a.Trim()).ToArray();
                return $"Formatted string: {string.Format(format_str, args)}";
            }
            catch (Exception ex)
            {
                return $"Format error: {ex.Message}";
            }
        }

        Dictionary<string, object?> values;
        try
        {
            values = JsonSerializer.Deserialize<Dictionary<string, object?>>(values_json)
                     ?? new Dictionary<string, object?>();
        }
        catch
        {
            values = new Dictionary<string, object?> { ["value"] = values_json };
        }

        if (include_builtins)
        {
            values["list"] = new List<object>();
            values["dict"] = new Dictionary<string, object>();
        }

        var s = format_str;
        foreach (var kv in values)
            s = s.Replace("{" + kv.Key + "}", kv.Value?.ToString() ?? "");

        var _unused = use_format_map;
        return $"Formatted string: {s}";
    }
}
