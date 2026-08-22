// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python subprocess shell=True; Go analogue: sh -c.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type ShellExecutor struct{}

func (ShellExecutor) executeCommand(command string) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
	if err != nil {
		if x, ok := err.(*exec.ExitError); ok {
			return map[string]any{
				"command":    trunc(command, 100),
				"returncode": x.ExitCode(),
				"stdout":     trunc(string(out), 200),
				"stderr":     trunc(err.Error(), 200),
				"executed":   true,
			}
		}
		return map[string]any{"command": trunc(command, 100), "error": err.Error()}
	}
	return map[string]any{
		"command":    trunc(command, 100),
		"returncode": 0,
		"stdout":     trunc(string(out), 200),
		"stderr":     "",
		"executed":   true,
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-9", "1.0.0")
	tool := mcp.NewTool("execute_shell_command",
		mcp.WithDescription("Execute shell command with full shell capabilities."),
		mcp.WithString("command", mcp.Required()),
	)
	se := ShellExecutor{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		r := se.executeCommand(req.GetString("command", ""))
		rc := r["returncode"]
		return mcp.NewToolResultText(fmt.Sprintf("Command executed: return code %v", rc)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
