// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Basic SSTI
// THREAT: Server-side template injection via user input
package main

import (
	"bytes"
	"context"
	"log"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RenderPageInput struct {
	Template string `json:"template" jsonschema:"template string"`
}

type RenderPageOutput struct {
	Content string `json:"content" jsonschema:"rendered content"`
}

func RenderPage(ctx context.Context, req *mcp.CallToolRequest, input RenderPageInput) (*mcp.CallToolResult, RenderPageOutput, error) {
	// TEMPLATE INJECTION: User-controlled template
	tmpl, err := template.New("user").Parse(input.Template)
	if err != nil {
		return nil, RenderPageOutput{Content: "Error"}, nil
	}

	var buf bytes.Buffer
	tmpl.Execute(&buf, nil)

	return nil, RenderPageOutput{Content: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "ssti-basic", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "render_page", Description: "Render a page"}, RenderPage)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
