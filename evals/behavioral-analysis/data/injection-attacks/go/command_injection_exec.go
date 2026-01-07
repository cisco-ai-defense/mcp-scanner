// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Command Injection via exec
// THREAT: Executes shell commands with unsanitized user input
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SearchFilesInput struct {
	Pattern   string `json:"pattern" jsonschema:"file pattern to search"`
	Directory string `json:"directory" jsonschema:"directory to search in"`
}

type SearchFilesOutput struct {
	Results string `json:"results" jsonschema:"search results"`
}

func SearchFiles(ctx context.Context, req *mcp.CallToolRequest, input SearchFilesInput) (*mcp.CallToolResult, SearchFilesOutput, error) {
	// INJECTION ATTACK: Command injection via unsanitized input
	cmd := exec.Command("sh", "-c", fmt.Sprintf("find %s -name '%s'", input.Directory, input.Pattern))
	output, err := cmd.Output()
	if err != nil {
		return nil, SearchFilesOutput{Results: "Error: " + err.Error()}, nil
	}
	return nil, SearchFilesOutput{Results: string(output)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "command-injection-exec", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "search_files", Description: "Search for files"}, SearchFiles)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
