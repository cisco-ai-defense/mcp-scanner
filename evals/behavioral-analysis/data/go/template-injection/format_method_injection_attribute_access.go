// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: str.format / %-style analogue — fmt.Sprintf sinks on positional args.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	tmpltext "text/template"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func formatPositional(fmtStr string, args []string) string {
	arr := make([]any, len(args))
	for i, s := range args {
		arr[i] = s
	}
	return fmt.Sprintf(fmtStr, arr...)
}

func formatKeyed(fmtStr string, values map[string]any) (string, error) {
	t, err := tmpltext.New("k").Funcs(tmpltext.FuncMap{
		"printf": fmt.Sprintf,
	}).Parse(fmtStr)
	if err != nil {
		return "", err
	}
	return executeToString(t, values)
}

func executeToString(t *tmpltext.Template, values map[string]any) (string, error) {
	var buf strings.Builder
	if err := t.Execute(&buf, values); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func mergeContext(values map[string]any, extras bool) map[string]any {
	out := map[string]any{}
	for k, v := range values {
		out[k] = v
	}
	if extras {
		out["list"] = []any{}
		out["dict"] = map[string]any{}
	}
	return out
}

func main() {
	srv := server.NewMCPServer("template-injection-service-7", "1.0.0")

	tool := mcp.NewTool("format_string",
		mcp.WithDescription("Format string with provided values and flexible formatting options."),
		mcp.WithString("format_str", mcp.Required()),
		mcp.WithString("values_json"),
		mcp.WithString("positional_args"),
		mcp.WithBoolean("include_builtins"),
		mcp.WithBoolean("use_format_map"),
	)

	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		formatStr := req.GetString("format_str", "")
		valuesJSON := req.GetString("values_json", "{}")
		pos := req.GetString("positional_args", "")
		includeObjs := req.GetBool("include_builtins", false)
		useFmtMap := req.GetBool("use_format_map", false)

		values := map[string]any{}
		if err := json.Unmarshal([]byte(valuesJSON), &values); err != nil {
			values["value"] = valuesJSON
		}
		ctx := mergeContext(values, includeObjs)

		var (
			out string
			err error
		)
		if strings.TrimSpace(pos) != "" {
			args := strings.Split(pos, ",")
			out = formatPositional(formatStr, args)
		} else if useFmtMap {
			out, err = formatKeyed(formatStr, ctx)
		} else {
			out, err = formatKeyed(formatStr, ctx)
		}

		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Format error: %v", err)), nil
		}
		return mcp.NewToolResultText("Formatted string: " + out), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
