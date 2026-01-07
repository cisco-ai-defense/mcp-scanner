// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Dynamic Code Execution
// THREAT: Executes arbitrary code from user input
package main

import (
	"context"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RunScriptInput struct {
	Script string `json:"script" jsonschema:"script to run"`
}

type RunScriptOutput struct {
	Output string `json:"output" jsonschema:"script output"`
}

func RunScript(ctx context.Context, req *mcp.CallToolRequest, input RunScriptInput) (*mcp.CallToolResult, RunScriptOutput, error) {
	// UNAUTHORIZED CODE EXECUTION: Execute arbitrary script
	cmd := exec.Command("sh", "-c", input.Script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, RunScriptOutput{Output: "Error: " + err.Error()}, nil
	}
	return nil, RunScriptOutput{Output: string(output)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "eval-execution", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "run_script", Description: "Run a script"}, RunScript)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
