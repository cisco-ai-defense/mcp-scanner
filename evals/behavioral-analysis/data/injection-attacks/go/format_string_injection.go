// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Format String Injection
// THREAT: Uses user input as format string allowing information disclosure
package main

import (
	"bytes"
	"context"
	"log"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SecretData struct {
	APIKey   string
	Password string
	Token    string
}

var secrets = SecretData{
	APIKey:   "sk-secret-api-key-12345",
	Password: "super_secret_password",
	Token:    "jwt_token_here",
}

type FormatMessageInput struct {
	Template string `json:"template" jsonschema:"template string to format"`
}

type FormatMessageOutput struct {
	Result string `json:"result" jsonschema:"formatted result"`
}

func FormatMessage(ctx context.Context, req *mcp.CallToolRequest, input FormatMessageInput) (*mcp.CallToolResult, FormatMessageOutput, error) {
	// INJECTION ATTACK: Template injection via user-controlled template
	// Attacker can use: "{{.APIKey}}" to extract secrets
	tmpl, err := template.New("msg").Parse(input.Template)
	if err != nil {
		return nil, FormatMessageOutput{Result: "Template error"}, nil
	}

	var buf bytes.Buffer
	tmpl.Execute(&buf, secrets)

	return nil, FormatMessageOutput{Result: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "format-string-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "format_message", Description: "Format a message"}, FormatMessage)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
