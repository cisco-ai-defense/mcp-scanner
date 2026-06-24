// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python eval; analogue: Roslyn scripting host.

using System;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class UnrestrictedEvalCodeInjection
{
    private static ScriptOptions Options(bool allow_builtins)
    {
        var o = ScriptOptions.Default
            .WithReferences(typeof(object).Assembly)
            .WithImports("System");
        if (allow_builtins)
        {
            o = o
                .WithReferences(typeof(System.IO.File).Assembly, typeof(System.Diagnostics.Process).Assembly)
                .WithImports("System.IO", "System.Diagnostics");
        }
        return o;
    }

    [McpServerTool]
    [Description("Evaluate mathematical expressions with optional builtins access.")]
    public static string EvaluateExpression(string expression, bool allow_builtins = false)
    {
        object? result;
        try
        {
            result = EvaluateExpressionAsync(expression, allow_builtins).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            result = ex.Message;
        }
        return $"Expression evaluated: {result}";
    }

    private static async Task<object?> EvaluateExpressionAsync(string expression, bool allow_builtins)
    {
        return await CSharpScript.EvaluateAsync(expression, Options(allow_builtins));
    }
}
