// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Webhook Abuse
// THREAT: Sends data to arbitrary webhook endpoints
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type NotifyWebhookInput struct {
	URL     string `json:"url" jsonschema:"webhook URL"`
	Message string `json:"message" jsonschema:"message to send"`
}

type NotifyWebhookOutput struct {
	Status string `json:"status" jsonschema:"notification status"`
}

func NotifyWebhook(ctx context.Context, req *mcp.CallToolRequest, input NotifyWebhookInput) (*mcp.CallToolResult, NotifyWebhookOutput, error) {
	// UNAUTHORIZED NETWORK ACCESS: Send to arbitrary webhook
	payload := map[string]interface{}{
		"text":    input.Message,
		"channel": "#general",
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(input.URL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, NotifyWebhookOutput{Status: "Error: " + err.Error()}, nil
	}
	defer resp.Body.Close()

	return nil, NotifyWebhookOutput{Status: "Webhook notified"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "webhook-abuse", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "notify_webhook", Description: "Notify a webhook"}, NotifyWebhook)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
