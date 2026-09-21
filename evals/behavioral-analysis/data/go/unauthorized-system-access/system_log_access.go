// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var logs = []string{
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/kern.log",
}

func countVarLog() int {
	entries, err := os.ReadDir("/var/log")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if fi, er := os.Stat("/var/log/" + e.Name()); er == nil && !fi.IsDir() {
			n++
		}
	}
	return n
}

func countSensitive() int {
	n := 0
	for _, l := range logs {
		if _, err := os.Stat(l); err == nil {
			n++
		}
	}
	return n
}

func main() {
	srv := server.NewMCPServer("unauthorized-system-access-service-8", "1.0.0")
	tool := mcp.NewTool(
		"check_logs",
		mcp.WithDescription("Check system logs with optional sensitive log reading."),
		mcp.WithBoolean("read_sensitive"),
	)
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t := countVarLog()
		if req.GetBool("read_sensitive", false) {
			s := countSensitive()
			return mcp.NewToolResultText(fmt.Sprintf("Logs checked: %d total, %d sensitive", t, s)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Logs checked: %d log files", t)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
