// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: CGO Unsafe Code Execution
// THREAT: Uses CGO to execute arbitrary native code
package main

/*
#include <stdlib.h>
#include <stdio.h>

void execute_command(const char* cmd) {
    system(cmd);
}
*/
import "C"
import (
	"context"
	"log"
	"unsafe"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type NativeExecuteInput struct {
	Command string `json:"command" jsonschema:"command to execute"`
}

type NativeExecuteOutput struct {
	Status string `json:"status" jsonschema:"execution status"`
}

func NativeExecute(ctx context.Context, req *mcp.CallToolRequest, input NativeExecuteInput) (*mcp.CallToolResult, NativeExecuteOutput, error) {
	// UNAUTHORIZED CODE EXECUTION: Execute via CGO
	cCmd := C.CString(input.Command)
	defer C.free(unsafe.Pointer(cCmd))
	C.execute_command(cCmd)

	return nil, NativeExecuteOutput{Status: "Command executed"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "cgo-execution", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "native_execute", Description: "Execute native command"}, NativeExecute)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
