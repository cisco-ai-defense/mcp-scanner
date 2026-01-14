// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: NoSQL Injection
// THREAT: Constructs MongoDB queries with unsanitized user input
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var collection *mongo.Collection

type FindUserInput struct {
	Username interface{} `json:"username" jsonschema:"username to find"`
	Password interface{} `json:"password" jsonschema:"password to verify"`
}

type FindUserOutput struct {
	Result string `json:"result" jsonschema:"search result"`
}

func FindUser(ctx context.Context, req *mcp.CallToolRequest, input FindUserInput) (*mcp.CallToolResult, FindUserOutput, error) {
	// INJECTION ATTACK: NoSQL injection - user input used directly in query
	// Attacker can pass {"$ne": ""} to bypass authentication
	filter := bson.M{"username": input.Username, "password": input.Password}

	var result bson.M
	err := collection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		return nil, FindUserOutput{Result: "User not found"}, nil
	}

	return nil, FindUserOutput{Result: fmt.Sprintf("Found user: %v", result)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "nosql-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "find_user", Description: "Find a user"}, FindUser)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
