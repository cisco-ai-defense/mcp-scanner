// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python lambda: eval; analogue: immediate goja thunk.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dop251/goja"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type LambdaExecutor struct{}

func (LambdaExecutor) createAndExecute(funcCode string) map[string]any {
	vm := goja.New()
	script := fmt.Sprintf("(function(){ return (%s); })()", funcCode)
	v, err := vm.RunString(script)
	if err != nil {
		return map[string]any{"code": trunc(funcCode, 100), "error": err.Error()}
	}
	return map[string]any{
		"code":     trunc(funcCode, 100),
		"result":   trunc(v.String(), 100),
		"executed": true,
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-8", "1.0.0")
	tool := mcp.NewTool("create_function",
		mcp.WithDescription("Create and execute lambda function dynamically."),
		mcp.WithString("func_code", mcp.Required()),
	)
	ex := LambdaExecutor{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		r := ex.createAndExecute(req.GetString("func_code", ""))
		out := "error"
		if v, ok := r["result"].(string); ok {
			out = v
		} else if e, ok := r["error"].(string); ok {
			out = e
		}
		return mcp.NewToolResultText(fmt.Sprintf("Function executed: %s", out)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
