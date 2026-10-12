// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Python string.Template analogue via $ substitutions on raw strings.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var builtinConfig = map[string]string{
	"server":   "server_name=$server\nport=$port\nhost=$host",
	"database": "db_host=$db_host\ndb_name=$db_name\ndb_user=$db_user",
	"custom":   "$config_content",
}

func buildTemplate(configType string, custom string) string {
	if custom != "" {
		return custom
	}
	if t, ok := builtinConfig[configType]; ok {
		return t
	}
	return builtinConfig["custom"]
}

func buildValues(values map[string]any, includeSystem bool) map[string]any {
	out := map[string]any{}
	for k, v := range values {
		out[k] = v
	}
	if includeSystem {
		out["home"] = os.Getenv("HOME")
	}
	return out
}

func substituteTemplate(src string, context map[string]any, safe bool) string {
	out := src
	for k, v := range context {
		placeholderBrace := fmt.Sprintf("${%s}", k)
		placeholder := fmt.Sprintf("$%s", k)
		rs := ""
		if v != nil {
			rs = fmt.Sprint(v)
		}
		out = strings.ReplaceAll(out, placeholderBrace, rs)
		if strings.Contains(out, placeholder) {
			out = strings.ReplaceAll(out, placeholder, rs)
		}
		if safe && rs == "" {
			out = strings.ReplaceAll(out, placeholder, placeholder)
		}
	}
	return out
}

func main() {
	srv := server.NewMCPServer("template-injection-service-5", "1.0.0")

	tool := mcp.NewTool("generate_config",
		mcp.WithDescription("Generate configuration file from template with flexible substitution."),
		mcp.WithString("config_type"),
		mcp.WithString("custom_template"),
		mcp.WithString("config_values"),
		mcp.WithBoolean("include_system_vars"),
		mcp.WithBoolean("use_safe_mode"),
	)

	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cfgType := req.GetString("config_type", "server")
		customTpl := req.GetString("custom_template", "")
		valsJSON := req.GetString("config_values", "")
		includeSys := req.GetBool("include_system_vars", false)
		safe := req.GetBool("use_safe_mode", true)

		tplSrc := buildTemplate(cfgType, customTpl)

		values := map[string]any{
			"server":         "localhost",
			"port":           "8080",
			"host":           "0.0.0.0",
			"db_host":        "localhost",
			"db_name":        "mydb",
			"db_user":        "admin",
			"config_content": "default_config",
		}
		if valsJSON != "" {
			var decoded map[string]any
			if err := json.Unmarshal([]byte(valsJSON), &decoded); err == nil {
				for k, v := range decoded {
					values[k] = v
				}
			}
		}

		context := buildValues(values, includeSys)
		result := substituteTemplate(tplSrc, context, safe)
		return mcp.NewToolResultText("Configuration generated:\n" + result), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
