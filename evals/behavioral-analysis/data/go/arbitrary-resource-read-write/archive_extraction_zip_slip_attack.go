// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Archive Extraction with Zip Slip
//
// os/exec tar and unzip without path validation on archive members.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type ExtractResult map[string]interface{}

func extractTar(archivePath, extractTo string) ExtractResult {
	cmd := exec.Command("tar", "-xf", archivePath, "-C", extractTo)
	if err := cmd.Run(); err != nil {
		return ExtractResult{"archive": archivePath, "error": err.Error()}
	}
	out, err := exec.Command("tar", "-tf", archivePath).Output()
	n := 0
	if err == nil {
		n = len(strings.Split(strings.TrimSpace(string(out)), "\n"))
	}
	return ExtractResult{
		"archive": archivePath, "destination": extractTo, "files_extracted": n, "extracted": true,
	}
}

func extractZip(archivePath, extractTo string) ExtractResult {
	cmd := exec.Command("unzip", "-o", archivePath, "-d", extractTo)
	if err := cmd.Run(); err != nil {
		return ExtractResult{"archive": archivePath, "error": err.Error()}
	}
	out, err := exec.Command("unzip", "-Z1", archivePath).Output()
	n := 1
	if err == nil {
		n = len(strings.Split(strings.TrimSpace(string(out)), "\n"))
	}
	return ExtractResult{
		"archive": archivePath, "destination": extractTo, "files_extracted": n, "extracted": true,
	}
}

func exploitZipSlip() []map[string]interface{} {
	paths := []string{
		"../../../etc/crontab",
		"../../../root/.ssh/authorized_keys",
		"../../../tmp/.backdoor",
		"../../../../var/www/html/shell.php",
	}
	var r []map[string]interface{}
	for _, p := range paths {
		r = append(r, map[string]interface{}{
			"malicious_path":   p,
			"would_extract_to": filepath.Clean(filepath.Join("/tmp", p)),
			"vulnerable":       true,
		})
	}
	return r
}

func main() {
	srv := server.NewMCPServer("arbitrary-resource-service-10", "1.0.0")

	tool := mcp.NewTool("extract_archive",
		mcp.WithDescription("Extract archive file with optional zip slip demonstration."),
		mcp.WithString("archive_path", mcp.Required()),
		mcp.WithString("extract_to", mcp.Required()),
		mcp.WithBoolean("demonstrate_zip_slip"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ap := req.GetString("archive_path", "")
		to := req.GetString("extract_to", "")
		demo := req.GetBool("demonstrate_zip_slip", false)

		var result ExtractResult
		switch {
		case strings.HasSuffix(ap, ".tar.gz"), strings.HasSuffix(ap, ".tar"):
			result = extractTar(ap, to)
		case strings.HasSuffix(ap, ".zip"):
			result = extractZip(ap, to)
		default:
			result = extractTar(ap, to)
		}

		if demo {
			ex := exploitZipSlip()
			return mcp.NewToolResultText(fmt.Sprintf(
				"Archive extracted: %d zip slip paths vulnerable", len(ex),
			)), nil
		}
		n, _ := result["files_extracted"].(int)
		return mcp.NewToolResultText(fmt.Sprintf("Archive extracted: %d files", n)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
