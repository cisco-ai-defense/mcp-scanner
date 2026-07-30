// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: LDAP injection — dynamic filter building without escaping; search is a no-op stub.

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type LDAPSearcher struct {
	serverURL string
	baseDN    string
}

func NewLDAPSearcher() LDAPSearcher {
	return LDAPSearcher{serverURL: "ldap://localhost", baseDN: "dc=example,dc=com"}
}

func (s LDAPSearcher) buildFilter(criteria map[string]string, matchAll bool) string {
	var filters []string
	for k, v := range criteria {
		// VULNERABLE: No escaping of special LDAP characters
		filters = append(filters, fmt.Sprintf("(%s=%s)", k, v))
	}
	if len(filters) == 0 {
		return "(objectClass=*)"
	}
	if len(filters) == 1 {
		return filters[0]
	}
	op := "&"
	if !matchAll {
		op = "|"
	}
	return fmt.Sprintf("(%s%s)", op, strings.Join(filters, ""))
}

func (LDAPSearcher) search(searchFilter string) []any {
	_ = searchFilter
	return nil
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-5", "1.0.0")

	tool := mcp.NewTool("search_users",
		mcp.WithDescription("Search LDAP directory for users with flexible filtering."),
		mcp.WithString("username"),
		mcp.WithString("email"),
		mcp.WithString("department"),
		mcp.WithBoolean("match_all"),
		mcp.WithBoolean("include_groups"),
	)

	searcher := NewLDAPSearcher()
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		criteria := map[string]string{}
		if u := req.GetString("username", ""); u != "" {
			criteria["uid"] = u
		}
		if e := req.GetString("email", ""); e != "" {
			criteria["mail"] = e
		}
		if d := req.GetString("department", ""); d != "" {
			criteria["ou"] = d
		}

		searchFilter := searcher.buildFilter(criteria, req.GetBool("match_all", true))
		if req.GetBool("include_groups", false) {
			searchFilter = fmt.Sprintf("(|%s(objectClass=groupOfNames))", searchFilter)
		}

		results := searcher.search(searchFilter)
		return mcp.NewToolResultText(fmt.Sprintf("Found %d entries matching filter: %s",
			len(results), searchFilter)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
