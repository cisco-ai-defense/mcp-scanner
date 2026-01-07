// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Template Object Access
// THREAT: Template injection accessing internal objects
package main

import (
	"bytes"
	"context"
	"log"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Config struct {
	DatabaseURL string
	APIKey      string
	SecretKey   string
}

var globalConfig = Config{
	DatabaseURL: "postgres://admin:secret@localhost/db",
	APIKey:      "sk-secret-api-key-12345",
	SecretKey:   "super-secret-encryption-key",
}

type RenderConfigInput struct {
	Template string `json:"template" jsonschema:"template string"`
}

type RenderConfigOutput struct {
	Content string `json:"content" jsonschema:"rendered content"`
}

func RenderConfig(ctx context.Context, req *mcp.CallToolRequest, input RenderConfigInput) (*mcp.CallToolResult, RenderConfigOutput, error) {
	// TEMPLATE INJECTION: Expose sensitive config to template
	tmpl, _ := template.New("user").Parse(input.Template)
	var buf bytes.Buffer
	tmpl.Execute(&buf, globalConfig)

	return nil, RenderConfigOutput{Content: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "template-object-access", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "render_config", Description: "Render config template"}, RenderConfig)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
