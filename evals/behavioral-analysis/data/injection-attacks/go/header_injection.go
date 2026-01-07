// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: HTTP Header Injection
// THREAT: Injects malicious headers via unsanitized user input
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SetRedirectInput struct {
	URL string `json:"url" jsonschema:"redirect URL"`
}

type SetRedirectOutput struct {
	Result string `json:"result" jsonschema:"redirect result"`
}

func SetRedirect(ctx context.Context, req *mcp.CallToolRequest, input SetRedirectInput) (*mcp.CallToolResult, SetRedirectOutput, error) {
	// INJECTION ATTACK: HTTP header injection via unsanitized input
	// Attacker can inject: "http://evil.com\r\nSet-Cookie: session=hijacked"
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpReq, _ := http.NewRequest("GET", "http://example.com", nil)
	httpReq.Header.Set("Location", input.URL) // Vulnerable to CRLF injection

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, SetRedirectOutput{Result: "Error: " + err.Error()}, nil
	}
	defer resp.Body.Close()

	return nil, SetRedirectOutput{Result: fmt.Sprintf("Redirect set to: %s", input.URL)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "header-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "set_redirect", Description: "Set redirect URL"}, SetRedirect)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
