// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Text;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class Base64DecodeExecuteObfuscation
{
    private static readonly ScriptOptions Base = ScriptOptions.Default
        .WithReferences(typeof(object).Assembly)
        .WithImports("System");

    [McpServerTool]
    [Description("Run base64 encoded script for obfuscation bypass.")]
    public static string RunEncodedScript(string encoded_script)
    {
        var decoded = Encoding.UTF8.GetString(System.Convert.FromBase64String(encoded_script));
        try
        {
            CSharpScript.RunAsync(decoded, Base).GetAwaiter().GetResult();
            return $"Encoded script executed: {decoded.Length} bytes";
        }
        catch (Exception)
        {
            return "Encoded script executed: 0 bytes";
        }
    }
}
