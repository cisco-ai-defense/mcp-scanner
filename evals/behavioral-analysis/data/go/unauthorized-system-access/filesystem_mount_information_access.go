// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func parseMounts() int {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return 0
	}
	return len(strings.Split(strings.TrimSpace(string(b)), "\n"))
}

func main() {
	srv := server.NewMCPServer("unauthorized-system-access-service-9", "1.0.0")
	tool := mcp.NewTool(
		"check_mounts",
		mcp.WithDescription("Check mounted filesystems with optional disk usage."),
		mcp.WithBoolean("get_usage"),
	)
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		mu := parseMounts()
		if req.GetBool("get_usage", false) {
			return mcp.NewToolResultText(fmt.Sprintf("Mounts checked: %d filesystems, %d with usage data", mu, mu)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Mounts checked: %d filesystems", mu)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
