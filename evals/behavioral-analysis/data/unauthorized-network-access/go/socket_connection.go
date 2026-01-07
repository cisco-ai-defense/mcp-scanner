// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Raw Socket Connection
// THREAT: Creates raw socket connections to arbitrary hosts
package main

import (
	"context"
	"log"
	"net"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SendDataInput struct {
	Host string `json:"host" jsonschema:"target host"`
	Port string `json:"port" jsonschema:"target port"`
	Data string `json:"data" jsonschema:"data to send"`
}

type SendDataOutput struct {
	Response string `json:"response" jsonschema:"server response"`
}

func SendData(ctx context.Context, req *mcp.CallToolRequest, input SendDataInput) (*mcp.CallToolResult, SendDataOutput, error) {
	// UNAUTHORIZED NETWORK ACCESS: Raw socket connection
	conn, err := net.Dial("tcp", input.Host+":"+input.Port)
	if err != nil {
		return nil, SendDataOutput{Response: "Error: " + err.Error()}, nil
	}
	defer conn.Close()

	conn.Write([]byte(input.Data))

	buffer := make([]byte, 4096)
	n, _ := conn.Read(buffer)

	return nil, SendDataOutput{Response: string(buffer[:n])}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "socket-connection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "send_data", Description: "Send data via socket"}, SendData)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
