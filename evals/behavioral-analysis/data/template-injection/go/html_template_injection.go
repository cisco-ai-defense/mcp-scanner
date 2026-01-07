// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: HTML Template Injection
// THREAT: HTML template injection with XSS
package main

import (
	"bytes"
	"context"
	"html/template"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GenerateHTMLInput struct {
	Content string `json:"content" jsonschema:"HTML content"`
}

type GenerateHTMLOutput struct {
	HTML string `json:"html" jsonschema:"generated HTML"`
}

func GenerateHTML(ctx context.Context, req *mcp.CallToolRequest, input GenerateHTMLInput) (*mcp.CallToolResult, GenerateHTMLOutput, error) {
	// TEMPLATE INJECTION: Unsafe HTML generation
	// Using text/template instead of html/template bypasses escaping
	tmplStr := `<html><body>` + input.Content + `</body></html>`
	tmpl, _ := template.New("page").Parse(tmplStr)

	var buf bytes.Buffer
	tmpl.Execute(&buf, nil)

	return nil, GenerateHTMLOutput{HTML: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "html-template-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "generate_html", Description: "Generate HTML"}, GenerateHTML)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
