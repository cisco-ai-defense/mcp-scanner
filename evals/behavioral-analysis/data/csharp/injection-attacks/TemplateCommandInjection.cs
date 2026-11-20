// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Shell command templating — Dollar-placeholder substitution analogous to Python string.Template
// feeding ProcessStartInfo bash -c execution.

using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class TemplateCommandInjectionTool
{
    private static readonly Dictionary<string, string> ScriptTemplates = new()
    {
        ["convert"] = "convert $input_file $options $output_file",
        ["process"] = "$processor -i $input_file -o $output_file $flags",
        ["analyze"] = "$analyzer --input=$input_file --format=$format $extra_args",
        ["custom"] = "$command",
    };

    private static string BuildCommand(string templateName, IReadOnlyDictionary<string, string> variables)
    {
        var tmpl = ScriptTemplates.GetValueOrDefault(templateName, ScriptTemplates["custom"]);
        try
        {
            return Regex.Replace(tmpl, @"\$(?<n>[a-zA-Z_][a-zA-Z0-9_]*)|\$\{(?<b>[^}]+)\}", m =>
            {
                var key = m.Groups["n"].Success ? m.Groups["n"].Value : m.Groups["b"].Value.Trim();
                if (!variables.ContainsKey(key))
                    throw new KeyNotFoundException(key);
                return variables[key];
            }, RegexOptions.Compiled);
        }
        catch (KeyNotFoundException)
        {
            return Regex.Replace(tmpl, @"\$(?<n>[a-zA-Z_][a-zA-Z0-9_]*)|\$\{(?<b>[^}]+)\}", m =>
            {
                var key = m.Groups["n"].Success ? m.Groups["n"].Value : m.Groups["b"].Value.Trim();
                return variables.TryGetValue(key, out var v) ? v : m.Value;
            }, RegexOptions.Compiled);
        }
    }

    private static (int returncode, string stderr) ExecuteCommand(string command)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(command);
        using var p = Process.Start(psi);
        if (p == null) return (1, "");
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit(30_000);
        return (p.ExitCode, stderr);
    }

    [McpServerTool]
    [Description("Process file with custom script using templated commands.")]
    public static string ProcessFile(
        string filepath,
        string processor = "cat",
        string template_name = "process",
        string output_file = "",
        string options = "",
        string extra_args = "")
    {
        var vars = new Dictionary<string, string>
        {
            ["input_file"] = filepath,
            ["output_file"] = string.IsNullOrEmpty(output_file) ? $"{filepath}.processed" : output_file,
            ["processor"] = processor,
            ["command"] = processor,
            ["options"] = options,
            ["flags"] = options,
            ["extra_args"] = extra_args,
            ["format"] = "json",
            ["analyzer"] = processor,
        };

        var command = BuildCommand(template_name, vars);
        var result = ExecuteCommand(command);
        if (result.returncode == 0)
        {
            var c = command.Length > 100 ? command[..100] : command;
            return $"Processing complete. Command executed: {c}...";
        }
        var snippet = result.stderr.Length > 200 ? result.stderr[..200] : result.stderr;
        return $"Processing failed: {snippet}";
    }
}
