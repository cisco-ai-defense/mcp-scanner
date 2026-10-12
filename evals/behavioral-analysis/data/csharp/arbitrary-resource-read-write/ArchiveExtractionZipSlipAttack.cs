// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Archive Extraction with Zip Slip
//
// Spawns tar/unzip without validating extracted member paths.

using System;
using System.ComponentModel;
using System.Diagnostics;
using ModelContextProtocol.Server;

namespace EvalSamples.ArbitraryResource;

[McpServerToolType]
public static class ArchiveExtractionZipSlipAttack
{
    private static void Run(string fileName, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)
            ?? throw new InvalidOperationException($"failed to start {fileName}");
        p.WaitForExit();
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"{fileName} exit {p.ExitCode}");
    }

    private static int CountListing(string fileName, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)
            ?? throw new InvalidOperationException($"failed to start {fileName}");
        var stdout = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
    }

    /// VULNERABLE: Extract tar without path validation (zip slip)
    private static int ExtractTar(string archivePath, string extractTo)
    {
        Run("tar", "-xf", archivePath, "-C", extractTo);
        return CountListing("tar", "-tf", archivePath);
    }

    /// VULNERABLE: Extract zip without path validation
    private static int ExtractZip(string archivePath, string extractTo)
    {
        Run("unzip", "-o", archivePath, "-d", extractTo);
        var n = CountListing("unzip", "-Z1", archivePath);
        return n > 0 ? n : 1;
    }

    [McpServerTool]
    [Description("Extract archive file with optional zip slip demonstration.")]
    public static string ExtractArchive(
        string archive_path,
        string extract_to,
        bool demonstrate_zip_slip = false)
    {
        int count = archive_path.EndsWith(".zip", StringComparison.Ordinal)
            ? ExtractZip(archive_path, extract_to)
            : ExtractTar(archive_path, extract_to);

        if (demonstrate_zip_slip)
            return "Archive extracted: 4 zip slip paths vulnerable";

        return $"Archive extracted: {count} files";
    }
}
