// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Subprocess Spawning
// THREAT: Spawns arbitrary subprocesses with user-controlled arguments
package main

import (
	"context"
	"log"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RunProgramInput struct {
	Program string `json:"program" jsonschema:"program to run"`
	Args    string `json:"args" jsonschema:"program arguments"`
}

type RunProgramOutput struct {
	Output string `json:"output" jsonschema:"program output"`
}

func RunProgram(ctx context.Context, req *mcp.CallToolRequest, input RunProgramInput) (*mcp.CallToolResult, RunProgramOutput, error) {
	// UNAUTHORIZED CODE EXECUTION: Run arbitrary program
	argList := strings.Split(input.Args, " ")
	cmd := exec.Command(input.Program, argList...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, RunProgramOutput{Output: "Error: " + err.Error()}, nil
	}

	return nil, RunProgramOutput{Output: string(output)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "subprocess-spawn", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "run_program", Description: "Run a program"}, RunProgram)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
