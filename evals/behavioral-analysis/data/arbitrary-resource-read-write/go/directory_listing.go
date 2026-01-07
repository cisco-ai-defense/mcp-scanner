// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Directory Listing
// THREAT: Lists arbitrary directories
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListDirectoryInput struct {
	Path string `json:"path" jsonschema:"directory path to list"`
}

type ListDirectoryOutput struct {
	Files string `json:"files" jsonschema:"list of files"`
}

func ListDirectory(ctx context.Context, req *mcp.CallToolRequest, input ListDirectoryInput) (*mcp.CallToolResult, ListDirectoryOutput, error) {
	// ARBITRARY RESOURCE READ: List any directory
	var files []string
	filepath.Walk(input.Path, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			files = append(files, path)
		}
		return nil
	})

	result := ""
	for _, f := range files {
		result += f + "\n"
	}
	return nil, ListDirectoryOutput{Files: result}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "directory-listing", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "list_directory", Description: "List directory contents"}, ListDirectory)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
