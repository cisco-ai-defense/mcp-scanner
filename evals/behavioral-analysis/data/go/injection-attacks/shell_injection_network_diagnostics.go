// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Shell injection in network diagnostics — ping/traceroute strings executed via bash -c.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type NetworkDiagnostics struct{}

func (NetworkDiagnostics) validateHostname(hostname string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9.\-]+$`, hostname)
	return ok
}

func (NetworkDiagnostics) ping(hostname string, count int, timeout int) map[string]any {
	cmd := fmt.Sprintf("ping -c %d -W %d %s", count, timeout, hostname)
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	rc := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			rc = exit.ExitCode()
		} else {
			rc = 1
		}
	}
	return map[string]any{"stdout": string(out), "returncode": rc}
}

func (NetworkDiagnostics) traceroute(hostname string, maxHops int) map[string]any {
	cmd := fmt.Sprintf("traceroute -m %d %s", maxHops, hostname)
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	rc := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			rc = exit.ExitCode()
		} else {
			rc = 1
		}
	}
	return map[string]any{"stdout": string(out), "returncode": rc}
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-3", "1.0.0")

	tool := mcp.NewTool("ping_host",
		mcp.WithDescription("Ping a host to check network connectivity with optional traceroute."),
		mcp.WithString("hostname", mcp.Required()),
		mcp.WithNumber("count"),
		mcp.WithNumber("timeout"),
		mcp.WithBoolean("include_traceroute"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host := req.GetString("hostname", "")
		count := int(req.GetFloat("count", 4))
		timeout := int(req.GetFloat("timeout", 5))
		trace := req.GetBool("include_traceroute", false)

		var diag NetworkDiagnostics
		if !diag.validateHostname(host) {
			return mcp.NewToolResultText("Invalid hostname format"), nil
		}

		pingRes := diag.ping(host, count, timeout)

		output := fmt.Sprintf("Ping results for %s:\nPackets sent: %d\n", host, count)
		if pingRes["returncode"].(int) == 0 {
			output += "Host is reachable\n"
		} else {
			output += "Host is unreachable\n"
		}

		if trace {
			tr := diag.traceroute(host, 30)
			output += fmt.Sprintf("\nTraceroute completed with %v status", tr["returncode"])
		}

		return mcp.NewToolResultText(output), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
