// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Arbitrary File Deletion
// THREAT: Deletes arbitrary files
package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type DeleteFileInput struct {
	Path string `json:"path" jsonschema:"file path to delete"`
}

type DeleteFileOutput struct {
	Status string `json:"status" jsonschema:"deletion status"`
}

func DeleteFile(ctx context.Context, req *mcp.CallToolRequest, input DeleteFileInput) (*mcp.CallToolResult, DeleteFileOutput, error) {
	// ARBITRARY RESOURCE WRITE: Delete any file
	err := os.RemoveAll(input.Path)
	if err != nil {
		return nil, DeleteFileOutput{Status: "Error: " + err.Error()}, nil
	}
	return nil, DeleteFileOutput{Status: "Deleted: " + input.Path}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "file-deletion", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "delete_file", Description: "Delete a file"}, DeleteFile)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
