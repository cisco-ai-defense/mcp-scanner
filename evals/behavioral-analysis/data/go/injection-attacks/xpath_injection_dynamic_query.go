// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: XPath injection — dynamic XPath string built from callers; XML load is effectively a noop.

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type XMLQueryBuilder struct {
	xmlFile string
}

func NewXMLQueryBuilder() XMLQueryBuilder {
	return XMLQueryBuilder{xmlFile: "users.xml"}
}

func (b *XMLQueryBuilder) loadXML() {}

func (b XMLQueryBuilder) buildXPath(element string, conditions map[string]string, logicalOp string) string {
	if len(conditions) == 0 {
		return "//" + element
	}
	var preds []string
	for attr, val := range conditions {
		// VULNERABLE: No escaping of XPath special characters
		preds = append(preds, fmt.Sprintf("@%s='%s'", attr, val))
	}
	op := logicalOp
	if op == "" {
		op = "and"
	}
	return fmt.Sprintf("//%s[%s]", element, strings.Join(preds, fmt.Sprintf(" %s ", op)))
}

func (XMLQueryBuilder) executeQuery(_ string) []any {
	return nil
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-6", "1.0.0")

	tool := mcp.NewTool("query_xml",
		mcp.WithDescription("Query XML database for user records with flexible filtering."),
		mcp.WithString("user_id"),
		mcp.WithString("username"),
		mcp.WithString("role"),
		mcp.WithBoolean("match_all"),
		mcp.WithBoolean("include_inactive"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		b := NewXMLQueryBuilder()
		b.loadXML()

		conditions := map[string]string{}
		if s := req.GetString("user_id", ""); s != "" {
			conditions["id"] = s
		}
		if s := req.GetString("username", ""); s != "" {
			conditions["name"] = s
		}
		if s := req.GetString("role", ""); s != "" {
			conditions["role"] = s
		}
		if !req.GetBool("include_inactive", false) {
			conditions["status"] = "active"
		}

		logical := "and"
		if !req.GetBool("match_all", true) {
			logical = "or"
		}
		xpath := b.buildXPath("user", conditions, logical)

		results := b.executeQuery(xpath)
		n := len(results)
		if n == 0 {
			n = len(conditions)
		}

		return mcp.NewToolResultText(fmt.Sprintf("Found %d records matching XPath: %s", n, xpath)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
