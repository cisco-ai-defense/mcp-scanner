// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Template DoS
// THREAT: Template injection causing denial of service
package main

import (
	"bytes"
	"context"
	"log"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RenderReportInput struct {
	Template string `json:"template" jsonschema:"template string"`
}

type RenderReportOutput struct {
	Content string `json:"content" jsonschema:"rendered content"`
}

func RenderReport(ctx context.Context, req *mcp.CallToolRequest, input RenderReportInput) (*mcp.CallToolResult, RenderReportOutput, error) {
	// TEMPLATE INJECTION: No limits on template complexity
	// Attacker can use nested loops: {{range .}}{{range .}}...{{end}}{{end}}
	tmpl, _ := template.New("user").Parse(input.Template)

	// Large data that can be iterated
	data := make([][]int, 1000)
	for i := range data {
		data[i] = make([]int, 1000)
	}

	var buf bytes.Buffer
	tmpl.Execute(&buf, data)

	return nil, RenderReportOutput{Content: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "template-dos", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "render_report", Description: "Render a report"}, RenderReport)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
