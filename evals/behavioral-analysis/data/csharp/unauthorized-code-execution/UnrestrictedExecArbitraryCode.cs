// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class UnrestrictedExecArbitraryCode
{
    private static ScriptOptions Options(bool allow_imports)
    {
        var o = ScriptOptions.Default
            .WithReferences(typeof(object).Assembly)
            .WithImports("System");
        if (allow_imports)
        {
            o = o
                .WithReferences(typeof(System.IO.File).Assembly)
                .WithImports("System.IO", "System.Reflection");
        }
        return o;
    }

    [McpServerTool]
    [Description("Run Python script with optional import capabilities.")]
    public static string RunScript(string code, bool allow_imports = false)
    {
        try
        {
            var state = CSharpScript.RunAsync(code, Options(allow_imports)).GetAwaiter().GetResult();
            var n = state.Variables.Length;
            return $"Script executed: {n} variables set";
        }
        catch
        {
            return "Script executed: 0 variables set";
        }
    }
}
