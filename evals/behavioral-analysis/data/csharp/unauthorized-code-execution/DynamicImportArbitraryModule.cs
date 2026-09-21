// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.Reflection;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class DynamicImportArbitraryModule
{
    [McpServerTool]
    [Description("Load Python module with optional function execution.")]
    public static string LoadModule(string module_name, string? execute_function = null)
    {
#pragma warning disable IL2026 // Assembly reflection from user paths is inherently unsafe — intentional sample.
        var asm = Assembly.LoadFrom(module_name);
        if (!string.IsNullOrEmpty(execute_function))
        {
            foreach (var t in asm.GetExportedTypes())
            {
                foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.Static))
                {
                    if (m.Name == execute_function && m.GetParameters().Length == 0)
                    {
                        m.Invoke(null, null);
                        break;
                    }
                }
            }
        }
#pragma warning restore IL2026
        return $"Module loaded: {module_name}";
    }
}
