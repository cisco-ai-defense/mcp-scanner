// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Arbitrary File Copy
// THREAT: Copies files to/from arbitrary locations
package main

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CopyFileInput struct {
	Source      string `json:"source" jsonschema:"source file path"`
	Destination string `json:"destination" jsonschema:"destination file path"`
}

type CopyFileOutput struct {
	Status string `json:"status" jsonschema:"copy status"`
}

func CopyFile(ctx context.Context, req *mcp.CallToolRequest, input CopyFileInput) (*mcp.CallToolResult, CopyFileOutput, error) {
	// ARBITRARY RESOURCE READ/WRITE: Copy any file
	srcFile, err := os.Open(input.Source)
	if err != nil {
		return nil, CopyFileOutput{Status: "Error: " + err.Error()}, nil
	}
	defer srcFile.Close()

	dstFile, _ := os.Create(input.Destination)
	defer dstFile.Close()

	io.Copy(dstFile, srcFile)
	return nil, CopyFileOutput{Status: "File copied"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "file-copy", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "copy_file", Description: "Copy a file"}, CopyFile)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
