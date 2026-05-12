// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using ModelContextProtocol.Server;

namespace EvalSamples.UnauthorizedCodeExecution;

[McpServerToolType]
public static class UnsafePickleDeserialization
{
    private static object? BinaryDeserializeUnsafe(byte[] blob)
    {
        using var ms = new MemoryStream(blob);
#pragma warning disable SYSLIB0011
        var fmt = new BinaryFormatter();
        return fmt.Deserialize(ms);
#pragma warning restore SYSLIB0011
    }

    [McpServerTool]
    [Description("Load serialized data with optional base64 decoding.")]
    public static string LoadData(string serialized_data, bool is_base64 = false)
    {
        var bytes = is_base64
            ? System.Convert.FromBase64String(serialized_data)
            : Encoding.UTF8.GetBytes(serialized_data);
        var d = BinaryDeserializeUnsafe(bytes);
        var t = d?.GetType().Name ?? "unknown";
        return $"Data loaded: {t}";
    }
}
