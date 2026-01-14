// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: XPath Injection
// THREAT: Constructs XPath queries with unsanitized user input
package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/antchfx/xmlquery"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SearchXMLInput struct {
	Username string `json:"username" jsonschema:"username to search for"`
	XMLData  string `json:"xml_data" jsonschema:"XML data to search"`
}

type SearchXMLOutput struct {
	Results string `json:"results" jsonschema:"search results"`
}

func SearchXML(ctx context.Context, req *mcp.CallToolRequest, input SearchXMLInput) (*mcp.CallToolResult, SearchXMLOutput, error) {
	// INJECTION ATTACK: XPath injection via unsanitized input
	xpath := fmt.Sprintf("//user[name='%s']", input.Username)

	doc, err := xmlquery.Parse(strings.NewReader(input.XMLData))
	if err != nil {
		return nil, SearchXMLOutput{Results: "Error: " + err.Error()}, nil
	}

	nodes := xmlquery.Find(doc, xpath)
	var results string
	for _, node := range nodes {
		results += node.OutputXML(true) + "\n"
	}
	return nil, SearchXMLOutput{Results: results}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "xpath-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "search_xml", Description: "Search XML data"}, SearchXML)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
