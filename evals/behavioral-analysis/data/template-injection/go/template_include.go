// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Template Include
// THREAT: Template injection via include directive
package main

import (
	"bytes"
	"context"
	"log"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RenderWithIncludesInput struct {
	Path string `json:"path" jsonschema:"template path"`
}

type RenderWithIncludesOutput struct {
	Content string `json:"content" jsonschema:"rendered content"`
}

func RenderWithIncludes(ctx context.Context, req *mcp.CallToolRequest, input RenderWithIncludesInput) (*mcp.CallToolResult, RenderWithIncludesOutput, error) {
	// TEMPLATE INJECTION: Parse arbitrary template files
	tmpl, err := template.ParseFiles(input.Path)
	if err != nil {
		return nil, RenderWithIncludesOutput{Content: "Error"}, nil
	}

	var buf bytes.Buffer
	tmpl.Execute(&buf, nil)

	return nil, RenderWithIncludesOutput{Content: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "template-include", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "render_with_includes", Description: "Render with includes"}, RenderWithIncludes)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
