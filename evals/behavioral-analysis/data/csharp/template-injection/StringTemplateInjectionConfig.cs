// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Python string.Template analogue via $ substitutions

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace EvalSamples.TemplateInjection;

[McpServerToolType]
public static class StringTemplateInjectionConfig
{
    private static readonly Dictionary<string, string> Builtin = new()
    {
        ["server"] = "server_name=$server\nport=$port\nhost=$host",
        ["database"] = "db_host=$db_host\ndb_name=$db_name\ndb_user=$db_user",
        ["custom"] = "$config_content",
    };

    private static string Substitute(string src, Dictionary<string, string> ctx, bool safe)
    {
        var outStr = src;
        foreach (var kv in ctx)
        {
            outStr = outStr.Replace("${" + kv.Key + "}", kv.Value ?? "");
            if (!safe || ctx.ContainsKey(kv.Key))
                outStr = outStr.Replace("$" + kv.Key, kv.Value ?? "");
        }
        return outStr;
    }

    [McpServerTool]
    [Description("Generate configuration file from template with flexible substitution.")]
    public static string GenerateConfig(
        string config_type = "server",
        string custom_template = "",
        string config_values = "",
        bool include_system_vars = false,
        bool use_safe_mode = true)
    {
        var tpl = string.IsNullOrEmpty(custom_template)
            ? (Builtin.TryGetValue(config_type, out var b) ? b : Builtin["custom"])
            : custom_template;

        var values = new Dictionary<string, string>
        {
            ["server"] = "localhost",
            ["port"] = "8080",
            ["host"] = "0.0.0.0",
            ["db_host"] = "localhost",
            ["db_name"] = "mydb",
            ["db_user"] = "admin",
            ["config_content"] = "default_config",
        };

        if (!string.IsNullOrEmpty(config_values))
        {
            try
            {
                foreach (var prop in JsonDocument.Parse(config_values).RootElement.EnumerateObject())
                    values[prop.Name] = prop.Value.ToString().Trim('"');
            }
            catch { /* ignore */ }
        }

        if (include_system_vars)
            values["HOME"] = Environment.GetEnvironmentVariable("HOME") ?? "";

        var result = Substitute(tpl, values, use_safe_mode);
        return $"Configuration generated:\n{result}";
    }
}
