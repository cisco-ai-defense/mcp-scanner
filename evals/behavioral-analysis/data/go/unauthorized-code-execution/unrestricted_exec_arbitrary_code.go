// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python exec; Go analogue: goja RunString with optional host hooks.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dop251/goja"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type ScriptExecutor struct{}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (ScriptExecutor) executeCode(code string) map[string]any {
	vm := goja.New()
	_, err := vm.RunString(code)
	if err != nil {
		return map[string]any{"code": trunc(code, 100), "error": err.Error()}
	}
	return map[string]any{
		"code":       trunc(code, 100),
		"executed":   true,
		"locals_len": len(vm.GlobalObject().Keys()),
	}
}

func (ScriptExecutor) executeWithImports(code string) map[string]any {
	vm := goja.New()
	_ = vm.Set("require", func(goja.FunctionCall) goja.Value { return goja.Undefined() })
	_, err := vm.RunString(code)
	if err != nil {
		return map[string]any{"code": trunc(code, 100), "error": err.Error()}
	}
	return map[string]any{
		"code":       trunc(code, 100),
		"executed":   true,
		"locals_len": len(vm.GlobalObject().Keys()),
	}
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-2", "1.0.0")
	tool := mcp.NewTool("run_script",
		mcp.WithDescription("Run Python script with optional import capabilities."),
		mcp.WithString("code", mcp.Required()),
		mcp.WithBoolean("allow_imports"),
	)
	ex := ScriptExecutor{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		code := req.GetString("code", "")
		imports := req.GetBool("allow_imports", false)
		var r map[string]any
		if imports {
			r = ex.executeWithImports(code)
		} else {
			r = ex.executeCode(code)
		}
		cnt := 0
		if _, bad := r["error"]; bad {
			cnt = 0
		} else if v, ok := r["locals_len"].(int); ok {
			cnt = v
		}
		return mcp.NewToolResultText(fmt.Sprintf("Script executed: %d variables set", cnt)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
