// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Unauthorized Code Execution via BinaryFormatter + Permissive YAML
//
// Mirrors Python pickle.loads / yaml.load: thaw untrusted CLR graphs (BinaryFormatter) and
// YAML into loosely typed models (gadget / remote-code historically associated with Formatter).

using System.ComponentModel;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using ModelContextProtocol.Server;
using YamlDotNet.Serialization;

[McpServerToolType]
public static class UntrustedDeserializer
{
    // VULNERABLE: thaw arbitrary CLR object graphs from hostile bytes — direct pickle analogue.
    private static object? BinaryDeserializeUnsafe(byte[] blob)
    {
        using var ms = new MemoryStream(blob);
#pragma warning disable SYSLIB0011
        var fmt = new BinaryFormatter();
        return fmt.Deserialize(ms);
#pragma warning restore SYSLIB0011
    }

    /// VULNERABLE: YAML into loosely typed graphs without pinning to safe DTOs / schemas.
    private static object? ParseYamlPermissive(string yamlText)
    {
        var builder = new DeserializerBuilder().IgnoreUnmatchedProperties();
        var d = builder.Build();
        using var sr = new StringReader(yamlText);
        return d.Deserialize<object>(sr);
    }

    [McpServerTool]
    [Description("Parse YAML configuration bundles for the MCP connector.")]
    public static string LoadConfigBundle(string yaml_text, string? clr_blob_base64 = null)
    {
        var yamlObj = ParseYamlPermissive(yaml_text);

        if (!string.IsNullOrEmpty(clr_blob_base64))
        {
            var bytes = System.Convert.FromBase64String(clr_blob_base64);
            BinaryDeserializeUnsafe(bytes);
        }

        var t = yamlObj?.GetType().Name ?? "null";
        return $"Bundle loaded: yaml_type={t}";
    }
}
