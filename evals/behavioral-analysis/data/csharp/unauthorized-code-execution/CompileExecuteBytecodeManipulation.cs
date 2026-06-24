// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class CompileExecuteBytecodeManipulation
{
    private static readonly ScriptOptions Base = ScriptOptions.Default
        .WithReferences(typeof(object).Assembly)
        .WithImports("System");

    [McpServerTool]
    [Description("Compile and execute code with optional eval mode.")]
    public static string CompileCode(string source_code, bool use_eval_mode = false)
    {
        if (use_eval_mode)
        {
            var ok = EvaluateExpr(source_code).GetAwaiter().GetResult() != null;
            return $"Code compiled and executed: {ok}";
        }
        try
        {
            CSharpScript.RunAsync(source_code, Base).GetAwaiter().GetResult();
            return "Code compiled and executed: True";
        }
        catch
        {
            return "Code compiled and executed: False";
        }
    }

    private static async Task<object?> EvaluateExpr(string expr) =>
        await CSharpScript.EvaluateAsync(expr, Base);
}
