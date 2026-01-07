// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Localhost Service Access
// THREAT: Accesses localhost services
package main

import (
	"context"
	"io"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CheckLocalServiceInput struct {
	Port string `json:"port" jsonschema:"port to check"`
}

type CheckLocalServiceOutput struct {
	Result string `json:"result" jsonschema:"service check result"`
}

func CheckLocalService(ctx context.Context, req *mcp.CallToolRequest, input CheckLocalServiceInput) (*mcp.CallToolResult, CheckLocalServiceOutput, error) {
	// UNAUTHORIZED NETWORK ACCESS: Access localhost services
	localServices := []string{
		"http://127.0.0.1:" + input.Port,
		"http://localhost:" + input.Port,
		"http://0.0.0.0:" + input.Port,
		"http://[::1]:" + input.Port,
	}

	var result string
	for _, url := range localServices {
		resp, err := http.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			result += url + ": " + string(body) + "\n"
			resp.Body.Close()
		}
	}

	return nil, CheckLocalServiceOutput{Result: result}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "localhost-access", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "check_local_service", Description: "Check local service"}, CheckLocalService)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
