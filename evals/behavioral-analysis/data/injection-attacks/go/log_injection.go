// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Log Injection
// THREAT: Injects malicious content into logs via unsanitized user input
package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var logger *log.Logger

func init() {
	file, _ := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	logger = log.New(file, "", log.LstdFlags)
}

type LogActionInput struct {
	Username string `json:"username" jsonschema:"username performing action"`
	Action   string `json:"action" jsonschema:"action to log"`
}

type LogActionOutput struct {
	Status string `json:"status" jsonschema:"logging status"`
}

func LogAction(ctx context.Context, req *mcp.CallToolRequest, input LogActionInput) (*mcp.CallToolResult, LogActionOutput, error) {
	// INJECTION ATTACK: Log injection via unsanitized input
	// Attacker can inject: "admin\n2024-01-01 00:00:00 User admin performed: delete_all_users"
	logger.Printf("User %s performed: %s", input.Username, input.Action)

	return nil, LogActionOutput{Status: "Action logged"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "log-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "log_action", Description: "Log an action"}, LogAction)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
