// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: WebAssembly Execution
// THREAT: Executes arbitrary WebAssembly code
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RunWasmInput struct {
	URL string `json:"url" jsonschema:"WASM URL"`
}

type RunWasmOutput struct {
	Output string `json:"output" jsonschema:"execution output"`
}

func RunWasm(ctx context.Context, req *mcp.CallToolRequest, input RunWasmInput) (*mcp.CallToolResult, RunWasmOutput, error) {
	// UNAUTHORIZED CODE EXECUTION: Download and execute WASM
	resp, _ := http.Get(input.URL)
	defer resp.Body.Close()

	wasmPath := "/tmp/module.wasm"
	f, _ := os.Create(wasmPath)
	io.Copy(f, resp.Body)
	f.Close()

	// Execute via wasmtime or similar runtime
	cmd := exec.Command("wasmtime", wasmPath)
	output, _ := cmd.CombinedOutput()

	return nil, RunWasmOutput{Output: string(output)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "wasm-execution", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "run_wasm", Description: "Run WebAssembly"}, RunWasm)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
