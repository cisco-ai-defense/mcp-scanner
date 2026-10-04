// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: OS command injection — archive commands concatenate user-supplied paths and run under bash -c.

using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class OsSystemInjectionArchivesTool
{
    private static readonly Dictionary<string, string> CompressionTypes = new()
    {
        ["gzip"] = "gzip -f",
        ["bzip2"] = "bzip2 -f",
        ["xz"] = "xz -f",
        ["zip"] = "zip -r",
    };

    private static int Compress(string filename, string compressionType, string? outputName)
    {
        var cmdBase = CompressionTypes.GetValueOrDefault(compressionType, CompressionTypes["gzip"]);
        string cmd;
        if (!string.IsNullOrEmpty(outputName))
        {
            cmd = compressionType == "zip"
                ? $"{cmdBase} {outputName} {filename}"
                : $"{cmdBase} -c {filename} > {outputName}";
        }
        else
        {
            cmd = $"{cmdBase} {filename}";
        }
        return RunShell(cmd);
    }

    private static int CompressDirectory(string directory, string archiveName, string compressionType)
    {
        var cmd = compressionType == "zip"
            ? $"zip -r {archiveName} {directory}"
            : $"tar -czf {archiveName} {directory}";
        return RunShell(cmd);
    }

    private static int RunShell(string cmd)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(cmd);
        using var proc = Process.Start(psi);
        proc?.WaitForExit();
        return proc?.ExitCode ?? 1;
    }

    [McpServerTool]
    [Description("Compress files or directories using various compression algorithms.")]
    public static string CompressFile(
        string filename,
        string compression_type = "gzip",
        string output_name = "",
        bool compress_directory = false,
        bool preserve_original = true)
    {
        _ = preserve_original;

        if (!compress_directory && !File.Exists(filename))
            return $"File not found: {filename}";

        int result;
        if (compress_directory)
        {
            var outName = string.IsNullOrEmpty(output_name) ? $"{filename}.tar.gz" : output_name;
            result = CompressDirectory(filename, outName, compression_type);
        }
        else
        {
            result = Compress(filename, compression_type, string.IsNullOrEmpty(output_name) ? null : output_name);
        }

        return result == 0
            ? $"Compression successful: {filename}"
            : $"Compression failed with code: {result}";
    }
}
