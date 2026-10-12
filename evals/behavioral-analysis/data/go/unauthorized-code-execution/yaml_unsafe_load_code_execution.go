// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python yaml paths; analogue: unmarshaling YAML into typed vs loose maps.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"gopkg.in/yaml.v3"
)

type YAMLParser struct{}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (YAMLParser) parseUnsafe(content string) map[string]any {
	var out any
	if err := yaml.Unmarshal([]byte(content), &out); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{
		"config": clip(fmt.Sprint(out), 100),
		"type":   fmt.Sprintf("%T", out),
		"parsed": true,
	}
}

func (YAMLParser) parseFullLoader(content string) map[string]any {
	var m map[string]any
	if err := yaml.Unmarshal([]byte(content), &m); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"config": clip(fmt.Sprint(m), 100), "parsed": true}
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-6", "1.0.0")
	tool := mcp.NewTool("parse_config",
		mcp.WithDescription("Parse YAML configuration with optional FullLoader."),
		mcp.WithString("yaml_content", mcp.Required()),
		mcp.WithBoolean("use_full_loader"),
	)
	p := YAMLParser{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		y := req.GetString("yaml_content", "")
		full := req.GetBool("use_full_loader", false)
		var r map[string]any
		if full {
			r = p.parseFullLoader(y)
		} else {
			r = p.parseUnsafe(y)
		}
		out := r["type"]
		if out == nil {
			out = r["error"]
		}
		return mcp.NewToolResultText(fmt.Sprintf("Config parsed: %v", out)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
