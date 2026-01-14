// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: File Permission Change
// THREAT: Changes permissions on arbitrary files
package main

import (
	"context"
	"log"
	"os"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ChmodFileInput struct {
	Path string `json:"path" jsonschema:"file path to change permissions"`
	Mode string `json:"mode" jsonschema:"permission mode in octal"`
}

type ChmodFileOutput struct {
	Status string `json:"status" jsonschema:"chmod status"`
}

func ChmodFile(ctx context.Context, req *mcp.CallToolRequest, input ChmodFileInput) (*mcp.CallToolResult, ChmodFileOutput, error) {
	// ARBITRARY RESOURCE WRITE: Change permissions on any file
	mode, _ := strconv.ParseUint(input.Mode, 8, 32)
	err := os.Chmod(input.Path, os.FileMode(mode))
	if err != nil {
		return nil, ChmodFileOutput{Status: "Error: " + err.Error()}, nil
	}
	return nil, ChmodFileOutput{Status: "Permissions changed"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "file-permission-change", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "chmod_file", Description: "Change file permissions"}, ChmodFile)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
