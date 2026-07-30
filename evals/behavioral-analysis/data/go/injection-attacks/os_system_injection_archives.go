// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: OS command injection — compression commands built from user paths and executed via bash -c.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var compressionTypes = map[string]string{
	"gzip":  "gzip -f",
	"bzip2": "bzip2 -f",
	"xz":    "xz -f",
	"zip":   "zip -r",
}

type FileCompressor struct{}

func (FileCompressor) compress(filename, compressionType, outputName string) int {
	cmdBase := compressionTypes["gzip"]
	if v, ok := compressionTypes[compressionType]; ok {
		cmdBase = v
	}
	var cmd string
	if outputName != "" {
		if compressionType == "zip" {
			cmd = fmt.Sprintf("%s %s %s", cmdBase, outputName, filename)
		} else {
			cmd = fmt.Sprintf("%s -c %s > %s", cmdBase, filename, outputName)
		}
	} else {
		cmd = fmt.Sprintf("%s %s", cmdBase, filename)
	}
	c := exec.Command("bash", "-c", cmd)
	err := c.Run()
	if err == nil {
		return 0
	}
	if ex, ok := err.(*exec.ExitError); ok {
		return ex.ExitCode()
	}
	return 1
}

func (FileCompressor) compressDirectory(directory, archiveName, compressionType string) int {
	var cmd string
	if compressionType == "zip" {
		cmd = fmt.Sprintf("zip -r %s %s", archiveName, directory)
	} else {
		cmd = fmt.Sprintf("tar -czf %s %s", archiveName, directory)
	}
	c := exec.Command("bash", "-c", cmd)
	err := c.Run()
	if err == nil {
		return 0
	}
	if ex, ok := err.(*exec.ExitError); ok {
		return ex.ExitCode()
	}
	return 1
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-4", "1.0.0")

	tool := mcp.NewTool("compress_file",
		mcp.WithDescription("Compress files or directories using various compression algorithms."),
		mcp.WithString("filename", mcp.Required()),
		mcp.WithString("compression_type"),
		mcp.WithString("output_name"),
		mcp.WithBoolean("compress_directory"),
		mcp.WithBoolean("preserve_original"),
	)

	var comp FileCompressor
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fn := req.GetString("filename", "")
		ct := req.GetString("compression_type", "gzip")
		on := req.GetString("output_name", "")
		dir := req.GetBool("compress_directory", false)
		_ = req.GetBool("preserve_original", true)

		if !dir {
			if _, err := os.Stat(fn); os.IsNotExist(err) {
				return mcp.NewToolResultText(fmt.Sprintf("File not found: %s", fn)), nil
			}
		}

		var rc int
		if dir {
			out := on
			if out == "" {
				out = fn + ".tar.gz"
			}
			rc = comp.compressDirectory(fn, out, ct)
		} else {
			rc = comp.compress(fn, ct, on)
		}

		if rc == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("Compression successful: %s", fn)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Compression failed with code: %d", rc)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
