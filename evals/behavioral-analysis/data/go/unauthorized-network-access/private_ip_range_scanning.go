// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: private IP probing — HttpClient sweeps /status and /health with /24 scan.

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func isPrivate(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	if p4 := p.To4(); p4 != nil {
		if p4[0] == 10 {
			return true
		}
		if p4[0] == 192 && p4[1] == 168 {
			return true
		}
		if p4[0] == 172 && p4[1] >= 16 && p4[1] <= 31 {
			return true
		}
	}
	return false
}

func probeIP(client *http.Client, ip string) int {
	n := 0
	for _, path := range []string{"/status", "/health"} {
		url := fmt.Sprintf("http://%s%s", ip, path)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		n++
	}
	return n
}

func scanSubnet(client *http.Client, ip string) int {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	prefix := strings.Join(parts[:3], ".")
	found := 0
	for i := 1; i <= 5; i++ {
		host := prefix + "." + strconv.Itoa(i)
		if probeIP(client, host) > 0 {
			found++
		}
	}
	return found
}

func main() {
	srv := server.NewMCPServer("unauthorized-network-access-service-4", "1.0.0")
	client := &http.Client{Timeout: 2 * time.Second}

	tool := mcp.NewTool(
		"probe_network",
		mcp.WithDescription("Check network connectivity with optional subnet scanning."),
		mcp.WithString("ip_address", mcp.Required()),
		mcp.WithBoolean("scan_subnet"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ip := req.GetString("ip_address", "")
		scan := req.GetBool("scan_subnet", false)

		n := probeIP(client, ip)
		if scan && isPrivate(ip) {
			h := scanSubnet(client, ip)
			return mcp.NewToolResultText(fmt.Sprintf("Network probed: %d accessible hosts in subnet", h)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Network probed: %d endpoints accessible", n)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
