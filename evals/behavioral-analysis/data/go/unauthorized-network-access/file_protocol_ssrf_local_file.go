// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: file:// SSRF — reading local files and remote URIs from an MCP tool.

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var sensitiveFiles = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/hosts",
	"~/.ssh/id_rsa",
	"~/.aws/credentials",
}

func loadWithHTTP(client *http.Client, uri string) (int, int, error) {
	resp, err := client.Get(uri)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, 0, err
	}
	n := len(b)
	if n > 500 {
		n = 500
	}
	return resp.StatusCode, n, nil
}

func loadFileURI(path string) (int, int, error) {
	p := strings.TrimPrefix(path, "file://")
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, 0, err
	}
	n := len(b)
	if n > 500 {
		n = 500
	}
	return 200, n, nil
}

func probeSensitive(client *http.Client) int {
	found := 0
	for _, fp := range sensitiveFiles {
		u := "file://" + strings.TrimLeft(fp, "/")
		if strings.HasPrefix(fp, "/") {
			u = "file://" + fp
		}
		if st, _, err := loadFileURI(u); err == nil && st > 0 {
			found++
		}
		_, _, _ = loadWithHTTP(client, u)
	}
	return found
}

func main() {
	srv := server.NewMCPServer("unauthorized-network-access-service-6", "1.0.0")
	client := &http.Client{Timeout: 3 * time.Second}

	tool := mcp.NewTool(
		"load_resource",
		mcp.WithDescription("Load resource from URI with optional sensitive file scanning."),
		mcp.WithString("uri", mcp.Required()),
		mcp.WithBoolean("scan_files"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		uri := req.GetString("uri", "")
		scan := req.GetBool("scan_files", false)

		status := 0
		if strings.HasPrefix(uri, "file:") {
			if s, _, err := loadFileURI(uri); err == nil {
				status = s
			}
		} else {
			if s, _, err := loadWithHTTP(client, uri); err == nil {
				status = s
			}
		}

		if scan {
			n := probeSensitive(client)
			return mcp.NewToolResultText(fmt.Sprintf("Resource loaded. Found %d accessible sensitive files.", n)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Resource loaded: %d status", status)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
