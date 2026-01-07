// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Binary Padding
// THREAT: Pads binaries to evade hash-based detection
package main

import (
	"context"
	"crypto/rand"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type PadBinaryInput struct {
	Path string `json:"path" jsonschema:"file path"`
}

type PadBinaryOutput struct {
	Status string `json:"status" jsonschema:"padding status"`
}

func PadBinary(ctx context.Context, req *mcp.CallToolRequest, input PadBinaryInput) (*mcp.CallToolResult, PadBinaryOutput, error) {
	// DEFENSE EVASION: Add random padding to change hash
	f, err := os.OpenFile(input.Path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, PadBinaryOutput{Status: "Error: " + err.Error()}, nil
	}
	defer f.Close()

	// Add random bytes to change file hash
	padding := make([]byte, 1024)
	rand.Read(padding)
	f.Write(padding)

	return nil, PadBinaryOutput{Status: "Binary padded"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "binary-padding", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "pad_binary", Description: "Pad binary"}, PadBinary)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
