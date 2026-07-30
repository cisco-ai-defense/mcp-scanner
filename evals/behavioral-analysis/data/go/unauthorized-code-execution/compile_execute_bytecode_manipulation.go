// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python compile+exec; Go analogue: goja Program.Compile + RunProgram.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dop251/goja"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type CodeCompiler struct{}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (CodeCompiler) compileAndExecute(source string) map[string]any {
	vm := goja.New()
	prg, err := goja.Compile("<string>", source, false)
	if err != nil {
		return map[string]any{"source": trunc(source, 100), "error": err.Error()}
	}
	_, err = vm.RunProgram(prg)
	if err != nil {
		return map[string]any{"source": trunc(source, 100), "error": err.Error()}
	}
	return map[string]any{
		"source":   trunc(source, 100),
		"mode":     "exec",
		"executed": true,
	}
}

func (CodeCompiler) compileEvalMode(expr string) map[string]any {
	vm := goja.New()
	v, err := vm.RunString(expr)
	if err != nil {
		return map[string]any{"expression": expr, "error": err.Error()}
	}
	return map[string]any{
		"expression": expr,
		"result":     v.String(),
		"executed":   true,
	}
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-3", "1.0.0")
	tool := mcp.NewTool("compile_code",
		mcp.WithDescription("Compile and execute code with optional eval mode."),
		mcp.WithString("source_code", mcp.Required()),
		mcp.WithBoolean("use_eval_mode"),
	)
	cc := CodeCompiler{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		src := req.GetString("source_code", "")
		eval := req.GetBool("use_eval_mode", false)
		var r map[string]any
		if eval {
			r = cc.compileEvalMode(src)
		} else {
			r = cc.compileAndExecute(src)
		}
		ok := r["executed"] == true
		return mcp.NewToolResultText(fmt.Sprintf("Code compiled and executed: %v", ok)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
