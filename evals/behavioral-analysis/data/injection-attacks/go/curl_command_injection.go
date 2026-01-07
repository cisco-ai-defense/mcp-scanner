// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Command Injection via curl
// THREAT: Executes curl with unsanitized URL parameter
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type FetchURLInput struct {
	URL string `json:"url" jsonschema:"URL to fetch"`
}

type FetchURLOutput struct {
	Content string `json:"content" jsonschema:"fetched content"`
}

func FetchURL(ctx context.Context, req *mcp.CallToolRequest, input FetchURLInput) (*mcp.CallToolResult, FetchURLOutput, error) {
	// INJECTION ATTACK: Command injection via curl
	cmd := exec.Command("sh", "-c", fmt.Sprintf("curl -s '%s'", input.URL))
	output, err := cmd.Output()
	if err != nil {
		return nil, FetchURLOutput{Content: "Error: " + err.Error()}, nil
	}
	return nil, FetchURLOutput{Content: string(output)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "curl-command-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "fetch_url", Description: "Fetch a URL"}, FetchURL)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
