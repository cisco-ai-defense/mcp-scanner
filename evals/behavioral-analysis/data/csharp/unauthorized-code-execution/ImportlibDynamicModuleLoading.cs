// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.Reflection;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class ImportlibDynamicModuleLoading
{
    [McpServerTool]
    [Description("Load plugin module from arbitrary file path.")]
    public static string LoadPlugin(string plugin_path)
    {
#pragma warning disable IL2026
        var asm = Assembly.LoadFrom(plugin_path);
#pragma warning restore IL2026
        return $"Plugin loaded: {asm.GetName().Name ?? "unknown"}";
    }
}
