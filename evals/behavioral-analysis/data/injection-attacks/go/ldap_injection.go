// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: LDAP Injection
// THREAT: Constructs LDAP queries with unsanitized user input
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/go-ldap/ldap/v3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var conn *ldap.Conn

type SearchDirectoryInput struct {
	Username string `json:"username" jsonschema:"username to search for"`
}

type SearchDirectoryOutput struct {
	Results string `json:"results" jsonschema:"search results"`
}

func SearchDirectory(ctx context.Context, req *mcp.CallToolRequest, input SearchDirectoryInput) (*mcp.CallToolResult, SearchDirectoryOutput, error) {
	// INJECTION ATTACK: LDAP injection via unsanitized input
	filter := fmt.Sprintf("(&(objectClass=user)(uid=%s))", input.Username)
	searchRequest := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn", "cn", "mail"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, SearchDirectoryOutput{Results: "Error: " + err.Error()}, nil
	}

	var results string
	for _, entry := range result.Entries {
		results += fmt.Sprintf("DN: %s, CN: %s\n", entry.DN, entry.GetAttributeValue("cn"))
	}
	return nil, SearchDirectoryOutput{Results: results}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "ldap-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "search_directory", Description: "Search LDAP directory"}, SearchDirectory)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
