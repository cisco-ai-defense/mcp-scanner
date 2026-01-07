// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Template File Read
// THREAT: Template injection allowing file read
package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func readFile(path string) string {
	content, _ := os.ReadFile(path)
	return string(content)
}

type RenderTemplateInput struct {
	Template string `json:"template" jsonschema:"template string"`
}

type RenderTemplateOutput struct {
	Content string `json:"content" jsonschema:"rendered content"`
}

func RenderTemplate(ctx context.Context, req *mcp.CallToolRequest, input RenderTemplateInput) (*mcp.CallToolResult, RenderTemplateOutput, error) {
	// TEMPLATE INJECTION: Template with file read function
	funcMap := template.FuncMap{
		"readFile": readFile,
		"include":  readFile,
	}

	tmpl, _ := template.New("user").Funcs(funcMap).Parse(input.Template)
	var buf bytes.Buffer
	tmpl.Execute(&buf, nil)

	return nil, RenderTemplateOutput{Content: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "template-file-read", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "render_template", Description: "Render a template"}, RenderTemplate)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
