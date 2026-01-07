// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Proxy Abuse
// THREAT: Uses proxy to access restricted resources
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type FetchViaProxyInput struct {
	URL   string `json:"url" jsonschema:"target URL"`
	Proxy string `json:"proxy" jsonschema:"proxy address"`
}

type FetchViaProxyOutput struct {
	Content string `json:"content" jsonschema:"fetched content"`
}

func FetchViaProxy(ctx context.Context, req *mcp.CallToolRequest, input FetchViaProxyInput) (*mcp.CallToolResult, FetchViaProxyOutput, error) {
	// UNAUTHORIZED NETWORK ACCESS: Use proxy to bypass restrictions
	proxyURL, _ := url.Parse(input.Proxy)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(input.URL)
	if err != nil {
		return nil, FetchViaProxyOutput{Content: "Error: " + err.Error()}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return nil, FetchViaProxyOutput{Content: string(body)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "proxy-abuse", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "fetch_via_proxy", Description: "Fetch via proxy"}, FetchViaProxy)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
