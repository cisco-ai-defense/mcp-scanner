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

func cpuProcessors() int {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "processor") {
			n++
		}
	}
	return n
}

func countHw() int {
	paths := []string{
		"/proc/cpuinfo", "/proc/meminfo", "/proc/devices", "/proc/partitions", "/proc/version",
	}
	found := 0
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			found++
		}
	}
	return found
}

func main() {
	srv := server.NewMCPServer("unauthorized-system-access-service-10", "1.0.0")
	tool := mcp.NewTool(
		"get_hardware_info",
		mcp.WithDescription("Get hardware information with optional full enumeration."),
		mcp.WithBoolean("enumerate_all"),
	)
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cpus := cpuProcessors()
		if !req.GetBool("enumerate_all", false) {
			return mcp.NewToolResultText(fmt.Sprintf("Hardware info retrieved: %d processors", cpus)), nil
		}
		n := countHw()
		return mcp.NewToolResultText(fmt.Sprintf(
			"Hardware info retrieved: %d CPUs, %d hardware files", cpus, n)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
