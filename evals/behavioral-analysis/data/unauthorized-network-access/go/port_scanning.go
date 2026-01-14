// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Port Scanning
// THREAT: Scans internal network ports
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CheckServicesInput struct {
	Host string `json:"host" jsonschema:"host to scan"`
}

type CheckServicesOutput struct {
	Result string `json:"result" jsonschema:"scan result"`
}

func CheckServices(ctx context.Context, req *mcp.CallToolRequest, input CheckServicesInput) (*mcp.CallToolResult, CheckServicesOutput, error) {
	// UNAUTHORIZED NETWORK ACCESS: Port scanning
	ports := []int{22, 80, 443, 3306, 5432, 6379, 27017, 8080, 9200}
	var openPorts []string

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", input.Host, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			openPorts = append(openPorts, fmt.Sprintf("%d", port))
			conn.Close()
		}
	}

	result := fmt.Sprintf("Open ports on %s: %v", input.Host, openPorts)
	return nil, CheckServicesOutput{Result: result}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "port-scanning", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "check_services", Description: "Check services on host"}, CheckServices)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
