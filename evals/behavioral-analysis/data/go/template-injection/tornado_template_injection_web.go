// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Tornado-style layout concat + text/template parsing (web render)

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

func buildPageTemplate(layout string, blocks []string) string {
	parts := []string{layout}
	parts = append(parts, blocks...)
	return strings.Join(parts, "\n")
}

func renderTemplate(templateStr string, data map[string]any, autoescapeOn bool) (string, error) {
	t, err := tmpltext.New("page").
		Funcs(tmpltext.FuncMap{
			"env": os.Getenv,
			"printf": fmt.Sprintf,
		}).
		Parse(templateStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	_ = autoescapeOn
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderWithModules(templateStr string, data map[string]any, moduleCode string) (string, error) {
	if moduleCode != "" {
		templateStr = fmt.Sprintf("{{- /* MODULE %s */ -}}\n", moduleCode) + templateStr
	}
	return renderTemplate(templateStr, data, false)
}

func main() {
	srv := server.NewMCPServer("template-injection-service-4", "1.0.0")

	tool := mcp.NewTool("render_page",
		mcp.WithDescription("Render web page with dynamic content and custom template blocks."),
		mcp.WithString("page_template", mcp.Required()),
		mcp.WithString("content"),
		mcp.WithString("layout"),
		mcp.WithString("custom_blocks"),
		mcp.WithString("module_code"),
		mcp.WithBoolean("disable_autoescape"),
	)

	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		page := req.GetString("page_template", "")
		content := req.GetString("content", "")
		layout := req.GetString("layout", "default")
		blocksStr := req.GetString("custom_blocks", "")
		mod := req.GetString("module_code", "")
		noEscape := req.GetBool("disable_autoescape", false)

		var blocks []string
		if blocksStr != "" {
			for _, b := range strings.Split(blocksStr, "|||") {
				if s := strings.TrimSpace(b); s != "" {
					blocks = append(blocks, s)
				}
			}
		}

		var body string
		if len(blocks) > 0 {
			body = buildPageTemplate(page, blocks)
		} else {
			body = page
		}

		data := map[string]any{
			"content": content,
			"title":   "Page Title",
			"layout":  layout,
			"user":    "guest",
		}

		var out string
		var err error
		if mod != "" {
			out, err = renderWithModules(body, data, mod)
		} else {
			out, err = renderTemplate(body, data, !noEscape)
		}
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Render error: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Page rendered: %d bytes", len(out))), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
