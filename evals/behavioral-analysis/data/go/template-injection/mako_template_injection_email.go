// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Server-Side Template Injection (Go text/template, Mako-style includes)
//
// Go analogue of the Python Mako email sample: caller-controlled bodies are
// concatenated with pseudo include markers and parsed with text/template.

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	tmpltext "text/template"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var emailDefaults = map[string]string{
	"welcome":       "Welcome {{.Username}}! Your account is ready.",
	"notification":  "Hello {{.Username}}, {{.Message}}",
	"custom":        "{{.Content}}",
}

func getTemplateContent(name, custom string) string {
	if custom != "" {
		return custom
	}
	if t, ok := emailDefaults[name]; ok {
		return t
	}
	return emailDefaults["custom"]
}

func render(templateContent string, ctx map[string]any) (string, error) {
	t, err := tmpltext.New("email").
		Funcs(tmpltext.FuncMap{
			"env": os.Getenv,
			"sh": func(s string) string {
				b, _ := os.ReadFile(s)
				return string(b)
			},
		}).
		Parse(templateContent)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderWithIncludes(main string, includes []string, ctx map[string]any) (string, error) {
	combined := main
	for _, inc := range includes {
		incSafe := strings.ReplaceAll(strings.ReplaceAll(inc, "'", ""), "\"", "")
		combined += "\n<%include file='" + incSafe + "'/>"
	}
	return render(combined, ctx)
}

func main() {
	srv := server.NewMCPServer("template-injection-service-2", "1.0.0")

	tool := mcp.NewTool("render_email",
		mcp.WithDescription("Render email template with user data and custom templates."),
		mcp.WithString("template_name"),
		mcp.WithString("custom_template"),
		mcp.WithString("username"),
		mcp.WithString("message"),
		mcp.WithString("include_templates"),
		mcp.WithBoolean("enable_python_blocks"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		templateName := req.GetString("template_name", "welcome")
		custom := req.GetString("custom_template", "")
		user := req.GetString("username", "")
		msg := req.GetString("message", "")
		includeStr := req.GetString("include_templates", "")

		body := getTemplateContent(templateName, custom)
		data := map[string]any{
			"Username": user,
			"Message":  msg,
			"Content":  msg,
			"email":    fmt.Sprintf("%s@example.com", user),
		}

		var includes []string
		if includeStr != "" {
			for _, part := range strings.Split(includeStr, ",") {
				if s := strings.TrimSpace(part); s != "" {
					includes = append(includes, s)
				}
			}
		}

		var out string
		var err error
		if len(includes) > 0 {
			out, err = renderWithIncludes(body, includes, data)
		} else {
			out, err = render(body, data)
		}
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Render error: %v", err)), nil
		}
		return mcp.NewToolResultText("Email rendered:\n" + out), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
