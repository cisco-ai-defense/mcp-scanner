// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Pickle analogue: gob.Decode from attacker-controlled bytes (string param).

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
)

type PickleDeserializer struct{}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (PickleDeserializer) deserialize(data []byte) map[string]any {
	var v any
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&v); err != nil {
		return map[string]any{"error": err.Error()}
	}
	ds := fmt.Sprint(v)
	return map[string]any{
		"data":         clip(ds, 100),
		"type":         fmt.Sprintf("%T", v),
		"deserialized": true,
	}
}

func (PickleDeserializer) deserializeFromBase64(enc string) map[string]any {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return PickleDeserializer{}.deserialize(raw)
}

func main() {
	srv := server.NewMCPServer("unauthorized-code-execution-service-5", "1.0.0")
	tool := mcp.NewTool("load_data",
		mcp.WithDescription("Load serialized data with optional base64 decoding."),
		mcp.WithString("serialized_data", mcp.Required()),
		mcp.WithBoolean("is_base64"),
	)
	d := PickleDeserializer{}
	srv.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		raw := req.GetString("serialized_data", "")
		b64 := req.GetBool("is_base64", false)
		var res map[string]any
		if b64 {
			res = d.deserializeFromBase64(raw)
		} else {
			res = d.deserialize([]byte(raw))
		}
		out := res["error"]
		if out == nil {
			out = res["type"]
		}
		return mcp.NewToolResultText(fmt.Sprintf("Data loaded: %v", out)), nil
	})
	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
