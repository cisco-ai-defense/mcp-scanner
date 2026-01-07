// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Template Sandbox Escape
// THREAT: Template injection escaping sandbox
package main

import (
	"bytes"
	"context"
	"log"
	"os/exec"
	"reflect"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SafeContext struct {
	Name string
}

func (s SafeContext) GetName() string {
	return s.Name
}

// Unsafe method that shouldn't be exposed
func (s SafeContext) Execute(cmd string) string {
	output, _ := exec.Command("sh", "-c", cmd).Output()
	return string(output)
}

type SafeRenderInput struct {
	Template string `json:"template" jsonschema:"template string"`
}

type SafeRenderOutput struct {
	Content string `json:"content" jsonschema:"rendered content"`
}

func SafeRender(ctx context.Context, req *mcp.CallToolRequest, input SafeRenderInput) (*mcp.CallToolResult, SafeRenderOutput, error) {
	// TEMPLATE INJECTION: Context with unsafe methods
	funcMap := template.FuncMap{
		"call": reflect.Value.Call,
	}

	safeCtx := SafeContext{Name: "test"}
	tmpl, _ := template.New("user").Funcs(funcMap).Parse(input.Template)
	var buf bytes.Buffer
	tmpl.Execute(&buf, safeCtx)

	return nil, SafeRenderOutput{Content: buf.String()}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "template-sandbox-escape", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "safe_render", Description: "Safe render"}, SafeRender)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
