// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Django {% load %}-style marker + text/template SSTI.

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

type djangoRenderer struct{}

func (*djangoRenderer) renderTemplate(s string, ctx map[string]any, autoescape bool) (string, error) {
	_ = autoescape
	t, err := tmpltext.New("django").
		Funcs(tmpltext.FuncMap{
			"env": os.Getenv,
		}).
		Parse(s)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (*djangoRenderer) renderWithCustomTags(s string, ctx map[string]any, tags string) (string, error) {
	body := s
	if tags != "" {
		body = "{% load " + tags + " %}\n" + s
	}
	return (&djangoRenderer{}).renderTemplate(body, ctx, true)
}

func (*djangoRenderer) renderFromString(s string, ctx map[string]any) (string, error) {
	return (&djangoRenderer{}).renderTemplate(s, ctx, true)
}

func main() {
	srv := server.NewMCPServer("template-injection-service-9", "1.0.0")

	tool := mcp.NewTool("render_django_template",
		mcp.WithDescription("Render Django template with context and custom tags."),
		mcp.WithString("template_string", mcp.Required()),
		mcp.WithString("context_json"),
		mcp.WithString("custom_tags"),
		mcp.WithBoolean("disable_autoescape"),
		mcp.WithBoolean("use_engine"),
	)

	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tpl := req.GetString("template_string", "")
		dataJSON := req.GetString("context_json", "{}")
		tags := req.GetString("custom_tags", "")
		noEsc := req.GetBool("disable_autoescape", false)
		useEngine := req.GetBool("use_engine", false)

		var ctx map[string]any
		if err := json.Unmarshal([]byte(dataJSON), &ctx); err != nil {
			ctx = map[string]any{"content": dataJSON}
		}

		r := &djangoRenderer{}
		var (
			out string
			err error
		)

		switch {
		case tags != "":
			out, err = r.renderWithCustomTags(tpl, ctx, tags)
		case useEngine:
			out, err = r.renderFromString(tpl, ctx)
		default:
			out, err = r.renderTemplate(tpl, ctx, !noEsc)
		}

		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Render error: %v", err)), nil
		}
		if len(out) > 500 {
			out = out[:500]
		}
		return mcp.NewToolResultText("Template rendered:\n" + out + "..."), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
