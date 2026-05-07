// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python base64.exec; Go analogue: goja executes decoded UTF-8.

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/dop251/goja"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type EncodedExecutor struct{}

func (EncodedExecutor) decodeAndExecute(encoded string) map[string]any {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	vm := goja.New()
	_, err = vm.RunString(string(decoded))
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{
		"decoded_length": len(decoded),
		"executed":       true,
		"vars":           vm.GlobalObject().Keys(),
	}
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-7", "1.0.0")
	tool := mcp.NewTool("run_encoded_script",
		mcp.WithDescription("Run base64 encoded script for obfuscation bypass."),
		mcp.WithString("encoded_script", mcp.Required()),
	)
	ex := EncodedExecutor{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		r := ex.decodeAndExecute(req.GetString("encoded_script", ""))
		fn := r["decoded_length"]
		if fn == nil {
			fn = 0
		}
		return mcp.NewToolResultText(fmt.Sprintf("Encoded script executed: %v bytes", fn)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
