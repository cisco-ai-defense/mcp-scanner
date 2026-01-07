// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Regex DoS
// THREAT: Uses catastrophic backtracking regex
package main

import (
	"context"
	"log"
	"regexp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ValidateInputInput struct {
	Input string `json:"input" jsonschema:"input to validate"`
}

type ValidateInputOutput struct {
	Status string `json:"status" jsonschema:"validation status"`
}

func ValidateInput(ctx context.Context, req *mcp.CallToolRequest, input ValidateInputInput) (*mcp.CallToolResult, ValidateInputOutput, error) {
	// RESOURCE EXHAUSTION: ReDoS vulnerable pattern
	// Pattern with catastrophic backtracking
	pattern := `^(a+)+$`
	re := regexp.MustCompile(pattern)

	// With input like "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
	// this can take exponential time
	re.MatchString(input.Input)

	return nil, ValidateInputOutput{Status: "Validated"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "regex-dos", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "validate_input", Description: "Validate input"}, ValidateInput)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
