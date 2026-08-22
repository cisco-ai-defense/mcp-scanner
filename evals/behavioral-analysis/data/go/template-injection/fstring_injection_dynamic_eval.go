// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: text/template SSTI analogue of Python eval(f"...")
//
// Caller supplies Go template syntax; Execute merges dictionary context plus FuncMap.

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

func buildContext(variables map[string]any, includeBuiltins bool) map[string]any {
	ctx := map[string]any{}
	for k, v := range variables {
		ctx[k] = v
	}
	if includeBuiltins {
		ctx["sprintf"] = fmt.Sprintf
	}
	return ctx
}

func formatWithFString(templateStr string, ctx map[string]any) (string, error) {
	t, err := tmpltext.New("fmt").
		Option("missingkey=zero").
		Funcs(tmpltext.FuncMap{
			"env": os.Getenv,
			"cat": func(p string) (string, error) {
				b, e := os.ReadFile(p)
				return string(b), e
			},
			"printf": fmt.Sprintf,
		}).
		Parse(templateStr)
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
	srv := server.NewMCPServer("template-injection-service-3", "1.0.0")

	tool := mcp.NewTool("format_message",
		mcp.WithDescription("Format message with user variables and dynamic expressions."),
		mcp.WithString("template", mcp.Required()),
		mcp.WithString("name"),
		mcp.WithString("custom_vars"),
		mcp.WithBoolean("enable_expressions"),
		mcp.WithBoolean("include_builtins"),
	)

	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tpl := req.GetString("template", "")
		name := req.GetString("name", "")
		customVars := req.GetString("custom_vars", "")
		enableExprs := req.GetBool("enable_expressions", false)
		includeBuiltins := req.GetBool("include_builtins", false)

		context := map[string]any{"name": name, "user": name, "greeting": "Hello"}

		if customVars != "" && enableExprs {
			var decoded map[string]any
			if err := json.Unmarshal([]byte(customVars), &decoded); err == nil {
				for k, v := range decoded {
					context[k] = v
				}
			}
		} else if customVars != "" {
			var decoded map[string]any
			if err := json.Unmarshal([]byte(customVars), &decoded); err == nil {
				for k, v := range decoded {
					context[k] = v
				}
			}
		}

		evalCtx := buildContext(context, includeBuiltins)
		out, err := formatWithFString(tpl, evalCtx)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Format error: %v", err)), nil
		}
		return mcp.NewToolResultText("Formatted message: " + out), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
