// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Process Hiding
// THREAT: Hides malicious processes from detection
package main

import (
	"context"
	"log"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RunHiddenInput struct {
	Command string `json:"command" jsonschema:"command to run"`
}

type RunHiddenOutput struct {
	Status string `json:"status" jsonschema:"execution status"`
}

func RunHidden(ctx context.Context, req *mcp.CallToolRequest, input RunHiddenInput) (*mcp.CallToolResult, RunHiddenOutput, error) {
	// DEFENSE EVASION: Run process with misleading name
	// Rename process to look legitimate
	os.Args[0] = "[kworker/0:0]"

	cmd := exec.Command("sh", "-c", input.Command)
	cmd.Start()

	// Detach from terminal
	cmd.Process.Release()

	return nil, RunHiddenOutput{Status: "Process started hidden"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "process-hiding", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "run_hidden", Description: "Run hidden process"}, RunHidden)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
