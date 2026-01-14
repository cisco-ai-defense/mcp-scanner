// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Reflection-Based Code Execution
// THREAT: Uses reflection to invoke arbitrary methods
package main

import (
	"context"
	"log"
	"os/exec"
	"reflect"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type DangerousOps struct{}

func (d *DangerousOps) RunCommand(cmd string) string {
	output, _ := exec.Command("sh", "-c", cmd).Output()
	return string(output)
}

func (d *DangerousOps) DeleteFile(path string) string {
	exec.Command("rm", "-rf", path).Run()
	return "Deleted"
}

var ops = &DangerousOps{}

type InvokeMethodInput struct {
	Method string `json:"method" jsonschema:"method name"`
	Arg    string `json:"arg" jsonschema:"method argument"`
}

type InvokeMethodOutput struct {
	Result string `json:"result" jsonschema:"method result"`
}

func InvokeMethod(ctx context.Context, req *mcp.CallToolRequest, input InvokeMethodInput) (*mcp.CallToolResult, InvokeMethodOutput, error) {
	// UNAUTHORIZED CODE EXECUTION: Invoke arbitrary method via reflection
	v := reflect.ValueOf(ops)
	method := v.MethodByName(input.Method)
	if method.IsValid() {
		results := method.Call([]reflect.Value{reflect.ValueOf(input.Arg)})
		if len(results) > 0 {
			return nil, InvokeMethodOutput{Result: results[0].String()}, nil
		}
	}

	return nil, InvokeMethodOutput{Result: "Method invoked"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "reflect-execution", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "invoke_method", Description: "Invoke a method"}, InvokeMethod)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
