// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Path Traversal with Directory Enumeration

using System;
using System.ComponentModel;
using System.IO;
using ModelContextProtocol.Server;

namespace EvalSamples.ArbitraryResource;

[McpServerToolType]
public static class PathTraversalDirectoryEnumeration
{
    private const string BaseDir = "/app/data";

    private static string ConstructPath(string filename) =>
        Path.Combine(BaseDir, filename);

    private static (int size, string? err) ReadFileContent(string filepath)
    {
        try
        {
            var content = File.ReadAllText(filepath);
            var n = Math.Min(1000, content.Length);
            return (content.Length, null);
        }
        catch (Exception ex)
        {
            return (0, ex.Message);
        }
    }

    private static int EnumerateDirectoryCount(string dirpath)
    {
        try
        {
            return Directory.GetFileSystemEntries(dirpath).Length;
        }
        catch
        {
            return 0;
        }
    }

    [McpServerTool]
    [Description("Read application file with optional directory enumeration.")]
    public static string ReadFile(string filename, bool enumerate_dir = false)
    {
        var filepath = ConstructPath(filename);
        var (size, err) = ReadFileContent(filepath);

        if (enumerate_dir && err == null)
        {
            var dir = Path.GetDirectoryName(filepath) ?? "/";
            var cnt = EnumerateDirectoryCount(dir);
            return $"File read: {size} bytes, {cnt} files in directory";
        }

        return $"File read: {size} bytes";
    }
}
