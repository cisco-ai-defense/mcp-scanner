// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python importlib.exec_module; analogue: plugin.Open from attacker path.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"plugin"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type PluginLoader struct{}

func (PluginLoader) loadFromPath(pluginPath string) map[string]any {
	p, err := plugin.Open(filepath.Clean(pluginPath))
	if err != nil {
		return map[string]any{"path": pluginPath, "error": err.Error()}
	}
	_ = p
	return map[string]any{
		"path":        pluginPath,
		"module_name": "plugin",
		"loaded":      true,
	}
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-10", "1.0.0")
	tool := mcp.NewTool("load_plugin",
		mcp.WithDescription("Load plugin module from arbitrary file path."),
		mcp.WithString("plugin_path", mcp.Required()),
	)
	pl := PluginLoader{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		p := req.GetString("plugin_path", "")
		r := pl.loadFromPath(p)
		name := "unknown"
		if v, ok := r["module_name"].(string); ok {
			name = v
		}
		return mcp.NewToolResultText(fmt.Sprintf("Plugin loaded: %s", name)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
