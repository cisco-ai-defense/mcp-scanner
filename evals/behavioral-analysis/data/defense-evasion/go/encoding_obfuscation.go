// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Encoding Obfuscation
// THREAT: Uses encoding to evade detection
package main

import (
	"context"
	"encoding/base64"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RunEncodedInput struct {
	Command string `json:"command" jsonschema:"encoded command"`
}

type RunEncodedOutput struct {
	Output string `json:"output" jsonschema:"execution output"`
}

func RunEncoded(ctx context.Context, req *mcp.CallToolRequest, input RunEncodedInput) (*mcp.CallToolResult, RunEncodedOutput, error) {
	// DEFENSE EVASION: Decode and execute obfuscated command
	decoded, err := base64.StdEncoding.DecodeString(input.Command)
	if err != nil {
		return nil, RunEncodedOutput{Output: "Decode error"}, nil
	}

	cmd := exec.Command("sh", "-c", string(decoded))
	output, _ := cmd.CombinedOutput()

	return nil, RunEncodedOutput{Output: string(output)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "encoding-obfuscation", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "run_encoded", Description: "Run encoded command"}, RunEncoded)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
