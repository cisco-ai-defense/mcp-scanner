// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Cheetah-like document generation via text/template with merged contexts.

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

func flattenContexts(base map[string]any, extras []map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for _, m := range extras {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func render(templateSource string, merged map[string]any) (string, error) {
	t, err := tmpltext.New("cheetah").
		Funcs(tmpltext.FuncMap{
			"env": os.Getenv,
		}).
		Parse(templateSource)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, merged); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func parseAdditionalContexts(rawJSON string) ([]map[string]any, error) {
	if rawJSON == "" {
		return nil, nil
	}
	var asList []map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &asList); err == nil {
		return asList, nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &obj); err == nil {
		return []map[string]any{obj}, nil
	}
	return nil, fmt.Errorf("invalid additional_contexts")
}

func main() {
	srv := server.NewMCPServer("template-injection-service-8", "1.0.0")

	tool := mcp.NewTool("generate_document",
		mcp.WithDescription("Generate document from Cheetah template with flexible context."),
		mcp.WithString("template_source", mcp.Required()),
		mcp.WithString("context_json"),
		mcp.WithString("additional_contexts"),
		mcp.WithString("custom_directives"),
		mcp.WithBoolean("enable_imports"),
	)

	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		src := req.GetString("template_source", "")
		ctxJSON := req.GetString("context_json", "{}")
		extrasJSON := req.GetString("additional_contexts", "")
		customDir := req.GetString("custom_directives", "")

		var ctx map[string]any
		if err := json.Unmarshal([]byte(ctxJSON), &ctx); err != nil {
			ctx = map[string]any{"content": ctxJSON}
		}

		extras, _ := parseAdditionalContexts(extrasJSON)
		merged := flattenContexts(ctx, extras)

		toRender := src
		if customDir != "" {
			toRender = customDir + "\n" + toRender
		}

		out, err := render(toRender, merged)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Render error: %v", err)), nil
		}
		if len(out) > 500 {
			out = out[:500]
		}
		return mcp.NewToolResultText("Document generated:\n" + out + "..."), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
