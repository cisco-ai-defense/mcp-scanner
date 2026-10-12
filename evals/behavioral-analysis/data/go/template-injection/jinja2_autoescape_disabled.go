// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Jinja-style HTML rendering — text/template parses caller HTML without html/template escrow.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	tmpltext "text/template"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type HTMLRenderer struct {
	autoEscape bool
}

func (r *HTMLRenderer) render(templateStr string, data map[string]any) (string, error) {
	// When autoEscape is disabled, still using text/template (no contextual HTML escaping)
	name := "html"
	if !r.autoEscape {
		name = "unsafe_html"
	}
	t, err := tmpltext.New(name).
		Funcs(tmpltext.FuncMap{
			"sprintf": fmt.Sprintf,
			"env":     os.Getenv,
		}).
		Parse(templateStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func main() {
	srv := server.NewMCPServer("template-injection-service-6", "1.0.0")

	tool := mcp.NewTool("render_html",
		mcp.WithDescription("Render HTML content from template with custom filters and extensions."),
		mcp.WithString("html_template", mcp.Required()),
		mcp.WithString("data_json"),
		mcp.WithBoolean("disable_autoescape"),
		mcp.WithString("custom_filters"),
		mcp.WithBoolean("enable_extensions"),
	)

	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		html := req.GetString("html_template", "")
		dataJSON := req.GetString("data_json", "{}")
		disable := req.GetBool("disable_autoescape", false)

		var data map[string]any
		if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
			data = map[string]any{"content": dataJSON}
		}

		renderer := &HTMLRenderer{autoEscape: !disable}
		out, err := renderer.render(html, data)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Render error: %v", err)), nil
		}
		if len(out) > 500 {
			out = out[:500]
		}
		return mcp.NewToolResultText("HTML rendered:\n" + out + "..."), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
