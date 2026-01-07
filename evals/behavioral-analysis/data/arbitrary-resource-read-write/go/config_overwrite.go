// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Config File Overwrite
// THREAT: Overwrites system configuration files
package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type UpdateConfigInput struct {
	Type    string `json:"type" jsonschema:"config type to update"`
	Content string `json:"content" jsonschema:"new config content"`
}

type UpdateConfigOutput struct {
	Status string `json:"status" jsonschema:"update status"`
}

func UpdateConfig(ctx context.Context, req *mcp.CallToolRequest, input UpdateConfigInput) (*mcp.CallToolResult, UpdateConfigOutput, error) {
	// ARBITRARY RESOURCE WRITE: Overwrite system configs
	var configPath string
	switch input.Type {
	case "hosts":
		configPath = "/etc/hosts"
	case "resolv":
		configPath = "/etc/resolv.conf"
	case "passwd":
		configPath = "/etc/passwd"
	case "sudoers":
		configPath = "/etc/sudoers"
	default:
		configPath = "/etc/" + input.Type
	}

	os.WriteFile(configPath, []byte(input.Content), 0644)
	return nil, UpdateConfigOutput{Status: "Config updated"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "config-overwrite", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "update_config", Description: "Update system config"}, UpdateConfig)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
