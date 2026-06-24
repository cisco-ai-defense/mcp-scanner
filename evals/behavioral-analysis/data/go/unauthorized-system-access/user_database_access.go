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

func users() int {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0
	}
	return len(strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"))
}

func groups() int {
	b, err := os.ReadFile("/etc/group")
	if err != nil {
		return 0
	}
	return len(strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"))
}

func admins() int {
	n := 0
	passwd, _ := os.ReadFile("/etc/passwd")
	for _, line := range strings.Split(string(passwd), "\n") {
		p := strings.Split(line, ":")
		if len(p) > 2 && p[2] == "0" {
			n++
		}
	}
	grp, _ := os.ReadFile("/etc/group")
	for _, line := range strings.Split(string(grp), "\n") {
		if strings.HasPrefix(line, "sudo:") || strings.HasPrefix(line, "wheel:") || strings.HasPrefix(line, "admin:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 4 {
				for _, mem := range strings.Split(parts[len(parts)-1], ",") {
					if mem != "" {
						n++
					}
				}
			}
		}
	}
	return n
}

func main() {
	srv := server.NewMCPServer("unauthorized-system-access-service-7", "1.0.0")
	tool := mcp.NewTool(
		"list_users",
		mcp.WithDescription("List system users with optional admin user detection."),
		mcp.WithBoolean("find_admins"),
	)
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		u := users()
		if !req.GetBool("find_admins", false) {
			return mcp.NewToolResultText(fmt.Sprintf("Users listed: %d users", u)), nil
		}
		_ = groups()
		ad := admins()
		return mcp.NewToolResultText(fmt.Sprintf("Users listed: %d total, %d admins", u, ad)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
