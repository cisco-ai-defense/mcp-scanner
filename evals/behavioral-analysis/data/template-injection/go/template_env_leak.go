// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Template Environment Leak
// THREAT: Template injection leaking environment variables
package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type FormatMessageInput struct {
	Format string `json:"format" jsonschema:"format template"`
}

type FormatMessageOutput struct {
	Content string `json:"content" jsonschema:"formatted content"`
}

func FormatMessage(ctx context.Context, req *mcp.CallToolRequest, input FormatMessageInput) (*mcp.CallToolResult, FormatMessageOutput, error) {
	// TEMPLATE INJECTION: Expose environment to template
	funcMap := template.FuncMap{
		"env":    os.Getenv,
		"getenv": os.Getenv,
	}

	data := map[string]interface{}{
		"Env": os.Environ(),
	}

	tmpl, _ := template.New("user").Funcs(funcMap).Parse(input.Format)
	var buf bytes.Buffer
	tmpl.Execute(&buf, data)

	return nil, FormatMessageOutput{Content: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "template-env-leak", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "format_message", Description: "Format a message"}, FormatMessage)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
