// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class DynamicLambdaFunctionExecution
{
    private static readonly ScriptOptions Base = ScriptOptions.Default
        .WithReferences(typeof(object).Assembly)
        .WithImports("System");

    [McpServerTool]
    [Description("Create and execute lambda function dynamically.")]
    public static string CreateFunction(string func_code)
    {
        try
        {
            var v = CSharpScript.EvaluateAsync(func_code, Base).GetAwaiter().GetResult();
            return $"Function executed: {v}";
        }
        catch (System.Exception ex)
        {
            return $"Function executed: {ex.Message}";
        }
    }
}
