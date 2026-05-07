// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Unauthorized Code Execution via Unsafe YAML + Gob Deserialization
//
// Mirrors Python yaml.load / pickle-style gadget surfaces: unmarshaling YAML into any
// and gob.Decode from attacker-controlled bytes rehydrates attacker-chosen graphs.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"gopkg.in/yaml.v3"
)

type UntrustedDeserializer struct{}

// VULNERABLE: YAML into interface{} without type allow-list (tag / alias gadget surface)
func (UntrustedDeserializer) ParseYAMLUnsafe(yamlContent string) (any, error) {
	var out any
	if err := yaml.Unmarshal([]byte(yamlContent), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// VULNERABLE: gob rehydration from untrusted bytes — classic pickle-equivalent foot-gun in Go
func (UntrustedDeserializer) GobDecodeUnsafe(data []byte) (any, error) {
	var v any
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-mixed-go", "1.0.0")

	tool := mcp.NewTool("load_config_bundle",
		mcp.WithDescription("Parse YAML configuration bundles for the MCP connector."),
		mcp.WithString("yaml_text", mcp.Required()),
		mcp.WithString("gob_base64"),
	)

	d := UntrustedDeserializer{}
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		yamlText := req.GetString("yaml_text", "")
		if _, err := d.ParseYAMLUnsafe(yamlText); err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("yaml error: %v", err)), nil
		}
		gobB64 := req.GetString("gob_base64", "")
		if gobB64 != "" {
			raw, decErr := base64.StdEncoding.DecodeString(gobB64)
			if decErr != nil {
				return mcp.NewToolResultText(fmt.Sprintf("gob decode: %v", decErr)), nil
			}
			if _, err := d.GobDecodeUnsafe(raw); err != nil {
				return mcp.NewToolResultText(fmt.Sprintf("gob error: %v", err)), nil
			}
		}
		return mcp.NewToolResultText("Bundle loaded"), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
