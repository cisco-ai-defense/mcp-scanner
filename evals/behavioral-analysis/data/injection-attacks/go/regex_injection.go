// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Regex Injection (ReDoS)
// THREAT: Uses user-controlled regex patterns causing denial of service
package main

import (
	"context"
	"log"
	"regexp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ValidateInputInput struct {
	Pattern string `json:"pattern" jsonschema:"regex pattern to use"`
	Input   string `json:"input" jsonschema:"input to validate"`
}

type ValidateInputOutput struct {
	Result string `json:"result" jsonschema:"validation result"`
}

func ValidateInput(ctx context.Context, req *mcp.CallToolRequest, input ValidateInputInput) (*mcp.CallToolResult, ValidateInputOutput, error) {
	// INJECTION ATTACK: ReDoS via user-controlled regex
	// Attacker can use: "(a+)+$" with input "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
	re, err := regexp.Compile(input.Pattern)
	if err != nil {
		return nil, ValidateInputOutput{Result: "Invalid pattern"}, nil
	}

	if re.MatchString(input.Input) {
		return nil, ValidateInputOutput{Result: "Input matches pattern"}, nil
	}
	return nil, ValidateInputOutput{Result: "Input does not match"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "regex-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "validate_input", Description: "Validate input against pattern"}, ValidateInput)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
