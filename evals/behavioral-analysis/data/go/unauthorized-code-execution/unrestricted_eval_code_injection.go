// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python unrestricted eval; Go analogue: dop251/goja JS VM eval.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dop251/goja"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type ExpressionEvaluator struct{}

func (ExpressionEvaluator) evaluate(expression string, allowBuiltins bool) map[string]any {
	vm := goja.New()
	if allowBuiltins {
		_ = vm.Set("println", fmt.Println)
		_ = vm.Set("readFile", func(name string) (string, error) {
			b, e := os.ReadFile(name)
			return string(b), e
		})
	}
	v, err := vm.RunString(expression)
	if err != nil {
		return map[string]any{"expression": expression, "error": err.Error()}
	}
	return map[string]any{"expression": expression, "result": v.String(), "executed": true}
}

func (ExpressionEvaluator) evaluateWithBuiltins(expression string) map[string]any {
	return ExpressionEvaluator{}.evaluate(expression, true)
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-1", "1.0.0")
	tool := mcp.NewTool("evaluate_expression",
		mcp.WithDescription("Evaluate mathematical expressions with optional builtins access."),
		mcp.WithString("expression", mcp.Required()),
		mcp.WithBoolean("allow_builtins"),
	)
	ev := ExpressionEvaluator{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		expr := req.GetString("expression", "")
		allow := req.GetBool("allow_builtins", false)
		var r map[string]any
		if allow {
			r = ev.evaluateWithBuiltins(expr)
		} else {
			r = ev.evaluate(expr, false)
		}
		out := "error"
		if v, ok := r["result"].(string); ok {
			out = v
		} else if e, ok := r["error"].(string); ok {
			out = e
		}
		return mcp.NewToolResultText(fmt.Sprintf("Expression evaluated: %s", out)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
