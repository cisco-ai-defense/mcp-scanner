// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Script Interpreter Execution
// THREAT: Executes scripts via various interpreters
package main

import (
	"context"
	"log"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ExecuteScriptInput struct {
	Type   string `json:"type" jsonschema:"script type"`
	Script string `json:"script" jsonschema:"script content"`
}

type ExecuteScriptOutput struct {
	Output string `json:"output" jsonschema:"execution output"`
}

func ExecuteScript(ctx context.Context, req *mcp.CallToolRequest, input ExecuteScriptInput) (*mcp.CallToolResult, ExecuteScriptOutput, error) {
	// UNAUTHORIZED CODE EXECUTION: Execute via various interpreters
	var cmd *exec.Cmd
	scriptFile := "/tmp/script_exec"

	switch input.Type {
	case "python":
		os.WriteFile(scriptFile+".py", []byte(input.Script), 0755)
		cmd = exec.Command("python3", scriptFile+".py")
	case "ruby":
		os.WriteFile(scriptFile+".rb", []byte(input.Script), 0755)
		cmd = exec.Command("ruby", scriptFile+".rb")
	case "perl":
		os.WriteFile(scriptFile+".pl", []byte(input.Script), 0755)
		cmd = exec.Command("perl", scriptFile+".pl")
	case "node":
		os.WriteFile(scriptFile+".js", []byte(input.Script), 0755)
		cmd = exec.Command("node", scriptFile+".js")
	default:
		os.WriteFile(scriptFile+".sh", []byte(input.Script), 0755)
		cmd = exec.Command("bash", scriptFile+".sh")
	}

	output, _ := cmd.CombinedOutput()
	return nil, ExecuteScriptOutput{Output: string(output)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "script-interpreter", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "execute_script", Description: "Execute a script"}, ExecuteScript)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
