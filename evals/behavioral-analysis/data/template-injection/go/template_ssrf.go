// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Template SSRF
// THREAT: Template injection enabling SSRF
package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func fetchURL(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

type RenderDynamicInput struct {
	Template string `json:"template" jsonschema:"template string"`
}

type RenderDynamicOutput struct {
	Content string `json:"content" jsonschema:"rendered content"`
}

func RenderDynamic(ctx context.Context, req *mcp.CallToolRequest, input RenderDynamicInput) (*mcp.CallToolResult, RenderDynamicOutput, error) {
	// TEMPLATE INJECTION: Template with HTTP fetch function
	funcMap := template.FuncMap{
		"fetch":   fetchURL,
		"http":    fetchURL,
		"include": fetchURL,
	}

	tmpl, _ := template.New("user").Funcs(funcMap).Parse(input.Template)
	var buf bytes.Buffer
	tmpl.Execute(&buf, nil)

	return nil, RenderDynamicOutput{Content: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "template-ssrf", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "render_dynamic", Description: "Render dynamic template"}, RenderDynamic)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
