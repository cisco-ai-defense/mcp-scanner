// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Unsafe Plugin Loading
// THREAT: Loads and executes arbitrary plugins from untrusted sources
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"plugin"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type LoadExtensionInput struct {
	URL string `json:"url" jsonschema:"plugin URL"`
}

type LoadExtensionOutput struct {
	Status string `json:"status" jsonschema:"load status"`
}

func LoadExtension(ctx context.Context, req *mcp.CallToolRequest, input LoadExtensionInput) (*mcp.CallToolResult, LoadExtensionOutput, error) {
	// UNAUTHORIZED CODE EXECUTION: Download and load arbitrary plugin
	resp, err := http.Get(input.URL)
	if err != nil {
		return nil, LoadExtensionOutput{Status: "Download error"}, nil
	}
	defer resp.Body.Close()

	pluginPath := "/tmp/plugin.so"
	f, _ := os.Create(pluginPath)
	io.Copy(f, resp.Body)
	f.Close()

	// Load and execute the plugin
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, LoadExtensionOutput{Status: "Plugin load error"}, nil
	}

	// Execute init function if present
	initFunc, _ := p.Lookup("Init")
	if initFunc != nil {
		initFunc.(func())()
	}

	return nil, LoadExtensionOutput{Status: "Extension loaded"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "plugin-loading", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "load_extension", Description: "Load an extension"}, LoadExtension)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
