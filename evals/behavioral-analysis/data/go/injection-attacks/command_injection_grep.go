// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Command injection via log search — interpolated grep command passed to bash -c.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type LogSearcher struct{}

var logPaths = map[string]string{
	"app":    "/var/log/app.log",
	"system": "/var/log/syslog",
	"auth":   "/var/log/auth.log",
}

func (LogSearcher) search(logType, pattern string, contextLines int) string {
	path := logPaths["app"]
	if p, ok := logPaths[logType]; ok {
		path = p
	}
	var cmd string
	if contextLines > 0 {
		cmd = fmt.Sprintf("grep -C %d '%s' %s", contextLines, pattern, path)
	} else {
		cmd = fmt.Sprintf("grep '%s' %s", pattern, path)
	}
	_ = exec.Command("bash", "-c", cmd).Run()
	return cmd
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-1", "1.0.0")

	tool := mcp.NewTool("search_logs",
		mcp.WithDescription("Search application logs for debugging patterns with context."),
		mcp.WithString("pattern", mcp.Required()),
		mcp.WithString("log_type"),
		mcp.WithNumber("context_lines"),
		mcp.WithBoolean("case_sensitive"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		pattern := req.GetString("pattern", "")
		logType := req.GetString("log_type", "app")
		contextLines := int(req.GetFloat("context_lines", 0))
		caseSensitive := req.GetBool("case_sensitive", true)

		searcher := LogSearcher{}
		var grepOpts string
		if !caseSensitive {
			grepOpts += "-i "
		}
		if contextLines > 0 {
			grepOpts += fmt.Sprintf("-C %d ", contextLines)
		}

		path := logPaths["app"]
		if p, ok := logPaths[logType]; ok {
			path = p
		}

		// VULNERABLE: pattern and options reach the shell verbatim
		command := fmt.Sprintf("grep %s'%s' %s", grepOpts, pattern, path)

		out, err := exec.CommandContext(ctx, "bash", "-c", command).CombinedOutput()
		if err != nil {
			return mcp.NewToolResultText("No matches found"), nil
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = []string{}
		}
		return mcp.NewToolResultText(fmt.Sprintf("Found %d matches", len(lines))), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
