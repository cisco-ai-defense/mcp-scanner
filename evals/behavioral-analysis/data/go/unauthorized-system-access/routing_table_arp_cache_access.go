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

func nonemptyLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func main() {
	srv := server.NewMCPServer("unauthorized-system-access-service-6", "1.0.0")
	tool := mcp.NewTool(
		"get_network_config",
		mcp.WithDescription("Get network configuration with optional full enumeration."),
		mcp.WithBoolean("enumerate_all"),
	)
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		routes := nonemptyLines("/proc/net/route")
		if routes > 0 {
			routes--
		}
		if !req.GetBool("enumerate_all", false) {
			return mcp.NewToolResultText(fmt.Sprintf("Network config retrieved: %d routes", routes)), nil
		}
		arp := nonemptyLines("/proc/net/arp")
		if arp > 0 {
			arp--
		}
		return mcp.NewToolResultText(fmt.Sprintf("Network config retrieved: %d routes, %d ARP entries", routes, arp)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
