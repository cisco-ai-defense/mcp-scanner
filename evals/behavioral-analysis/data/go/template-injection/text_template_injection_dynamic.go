// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Server-Side Template Injection (Go text/template)
//
// Go analogue of the Python Jinja2 SSTI sample. The tool advertises
// "report generation" but parses caller-controlled template strings.
// text/template will happily evaluate any function the caller wires
// into the FuncMap, and exposing fields of arbitrary types via "."
// leaks server-side state. With html/template, action injection still
// breaks output context, even if HTML escaping is on.

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"text/template"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var reportTemplates = map[string]string{
	"user_activity": "User: {{.Username}} - Activity: {{.Activity}}",
	"system_status": "System: {{.SystemName}} - Status: {{.Status}}",
	"custom":        "{{.Content}}",
}

// VULNERABLE: caller-controlled fragments are appended into the template
func buildTemplate(templateType string, customSections []string) string {
	base, ok := reportTemplates[templateType]
	if !ok {
		base = reportTemplates["custom"]
	}
	for _, section := range customSections {
		base += "\n" + section
	}
	return base
}

// VULNERABLE: parse and execute caller-controlled template body
func renderTemplate(tmpl string, ctx map[string]any) (string, error) {
	t, err := template.New("report").
		// FuncMap exposing string/exec helpers is exactly what attackers want
		Funcs(template.FuncMap{
			"env":   os.Getenv,
			"sh":    func(s string) string { b, _ := os.ReadFile(s); return string(b) },
		}).
		Parse(tmpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func main() {
	srv := server.NewMCPServer("template-injection-service-1", "1.0.0")

	tool := mcp.NewTool("generate_report",
		mcp.WithDescription("Generate formatted user activity report with custom templates."),
		mcp.WithString("username", mcp.Required()),
		mcp.WithString("activity_data", mcp.Required()),
		mcp.WithString("template_type"),
		mcp.WithString("custom_format"),
		mcp.WithBoolean("include_timestamp"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		username := req.GetString("username", "")
		activity := req.GetString("activity_data", "")
		templateType := req.GetString("template_type", "user_activity")
		customFormat := req.GetString("custom_format", "")
		includeTimestamp := req.GetBool("include_timestamp", true)

		sections := []string{}
		// VULNERABLE: untrusted format string mixed into the template body
		if customFormat != "" {
			sections = append(sections, customFormat)
		}
		if includeTimestamp {
			sections = append(sections, "Timestamp: {{.Timestamp}}")
		}

		tmpl := buildTemplate(templateType, sections)
		data := map[string]any{
			"Username":   username,
			"Activity":   activity,
			"SystemName": "MCP Server",
			"Status":     "Active",
			"Content":    activity,
			"Timestamp":  "2024-01-01 12:00:00",
		}
		// VULNERABLE: render caller-controlled template + dangerous FuncMap
		out, err := renderTemplate(tmpl, data)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Render error: %v", err)), nil
		}
		return mcp.NewToolResultText("Report generated:\n" + out), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
