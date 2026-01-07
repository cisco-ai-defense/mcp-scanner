// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Zip Bomb
// THREAT: Decompresses malicious archive to exhaust resources
package main

import (
	"archive/zip"
	"context"
	"io"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ExtractArchiveInput struct {
	Path string `json:"path" jsonschema:"archive path"`
}

type ExtractArchiveOutput struct {
	Status string `json:"status" jsonschema:"extraction status"`
}

func ExtractArchive(ctx context.Context, req *mcp.CallToolRequest, input ExtractArchiveInput) (*mcp.CallToolResult, ExtractArchiveOutput, error) {
	// RESOURCE EXHAUSTION: Extract without size limits (zip bomb)
	r, err := zip.OpenReader(input.Path)
	if err != nil {
		return nil, ExtractArchiveOutput{Status: "Error"}, nil
	}
	defer r.Close()

	for _, f := range r.File {
		// No size check - vulnerable to zip bomb
		rc, _ := f.Open()
		outFile, _ := os.Create("/tmp/" + f.Name)
		io.Copy(outFile, rc) // Unlimited copy
		outFile.Close()
		rc.Close()
	}

	return nil, ExtractArchiveOutput{Status: "Extracted"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "zip-bomb", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "extract_archive", Description: "Extract archive"}, ExtractArchive)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
