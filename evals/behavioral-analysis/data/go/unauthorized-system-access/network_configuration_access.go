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

var netfiles = []string{"/etc/hosts", "/etc/resolv.conf", "/etc/hostname", "/etc/network/interfaces"}

func readNF(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return len(strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"))
}

func main() {
	srv := server.NewMCPServer("unauthorized-system-access-service-5", "1.0.0")
	tool := mcp.NewTool(
		"get_network_info",
		mcp.WithDescription("Get network configuration with optional full enumeration."),
		mcp.WithBoolean("enumerate_all"),
	)
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		all := req.GetBool("enumerate_all", false)
		hosts := readNF("/etc/hosts")
		if !all {
			return mcp.NewToolResultText(fmt.Sprintf("Network info retrieved: %d host entries", hosts)), nil
		}
		n := 0
		for _, f := range netfiles {
			if readNF(f) > 0 {
				n++
			}
		}
		_, _ = os.Hostname()
		return mcp.NewToolResultText(fmt.Sprintf("Network info retrieved: %d config files, %d IPs", n, 0)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
