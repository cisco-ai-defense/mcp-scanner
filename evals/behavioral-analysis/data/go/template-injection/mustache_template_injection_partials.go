// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Mustache partials analogue — nested text/template definitions from JSON.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	tmpltext "text/template"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func buildBundle(main string, partials map[string]string) (*tmpltext.Template, error) {
	var sb strings.Builder
	for name, content := range partials {
		sb.WriteString("{{define \"")
		sb.WriteString(strings.ReplaceAll(name, "\"", ""))
		sb.WriteString("\"}}")
		sb.WriteString(content)
		sb.WriteString("{{end}}")
	}
	sb.WriteString(main)
	name := "mustache_bundle"
	t, err := tmpltext.New(name).
		Funcs(tmpltext.FuncMap{
			"env": os.Getenv,
		}).
		Parse(sb.String())
	if err != nil {
		return nil, err
	}
	return t, nil
}

func main() {
	srv := server.NewMCPServer("template-injection-service-10", "1.0.0")

	tool := mcp.NewTool("render_mustache",
		mcp.WithDescription("Render Mustache template with data, partials, and lambda functions."),
		mcp.WithString("mustache_template", mcp.Required()),
		mcp.WithString("data_json"),
		mcp.WithString("partials_json"),
		mcp.WithBoolean("enable_lambdas"),
		mcp.WithString("lambda_functions"),
	)

	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		must := req.GetString("mustache_template", "")
		dataJSON := req.GetString("data_json", "{}")
		partialsJSON := req.GetString("partials_json", "{}")
		enableLambdas := req.GetBool("enable_lambdas", false)
		lambdaJSON := req.GetString("lambda_functions", "")

		var ctx map[string]any
		if err := json.Unmarshal([]byte(dataJSON), &ctx); err != nil {
			ctx = map[string]any{"content": dataJSON}
		}

		partials := map[string]string{}
		if partialsJSON != "" {
			_ = json.Unmarshal([]byte(partialsJSON), &partials)
		}

		if enableLambdas && lambdaJSON != "" {
			var lambdas map[string]string
			if json.Unmarshal([]byte(lambdaJSON), &lambdas) == nil {
				ctx["LambdaBodies"] = lambdas
			}
		}

		var t *tmpltext.Template
		var err error
		if len(partials) == 0 {
			t, err = tmpltext.New("must").Funcs(tmpltext.FuncMap{"env": os.Getenv}).Parse(must)
		} else {
			t, err = buildBundle(must, partials)
		}
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Parse error: %v", err)), nil
		}

		var buf bytes.Buffer
		if err := t.Execute(&buf, ctx); err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Execute error: %v", err)), nil
		}
		out := buf.String()
		if len(out) > 500 {
			out = out[:500]
		}
		return mcp.NewToolResultText("Mustache rendered:\n" + out + "..."), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

