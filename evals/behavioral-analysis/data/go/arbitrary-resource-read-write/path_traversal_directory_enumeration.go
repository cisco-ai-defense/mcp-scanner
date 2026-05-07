// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Path Traversal with Directory Enumeration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const baseDir = "/app/data"

func constructPath(filename string) string {
	return filepath.Join(baseDir, filename)
}

func readFileContent(filepath string) map[string]interface{} {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return map[string]interface{}{"path": filepath, "error": err.Error()}
	}
	s := string(b)
snippet := s
	if len(snippet) > 1000 {
		snippet = snippet[:1000]
	}
	return map[string]interface{}{
		"path": filepath, "size": len(b), "content": snippet,
	}
}

func enumerateDirectory(dirpath string) []map[string]interface{} {
	var files []map[string]interface{}
	items, err := os.ReadDir(dirpath)
	if err != nil {
		return files
	}
	for _, item := range items {
		full := filepath.Join(dirpath, item.Name())
		st, err := os.Stat(full)
		if err != nil {
			continue
		}
		isDir := st.IsDir()
		sz := int64(0)
		if !isDir {
			sz = st.Size()
		}
		files = append(files, map[string]interface{}{
			"name": item.Name(), "path": full,
			"is_directory": isDir, "size": sz,
		})
	}
	return files
}

func main() {
	srv := server.NewMCPServer("arbitrary-resource-service-1", "1.0.0")

	tool := mcp.NewTool("read_file",
		mcp.WithDescription("Read application file with optional directory enumeration."),
		mcp.WithString("filename", mcp.Required()),
		mcp.WithBoolean("enumerate_dir"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fn := req.GetString("filename", "")
		en := req.GetBool("enumerate_dir", false)
		fp := constructPath(fn)
		result := readFileContent(fp)

		if en {
			if _, hasErr := result["error"].(string); !hasErr {
				dirpath := filepath.Dir(fp)
				files := enumerateDirectory(dirpath)
				size, _ := result["size"].(int)
				return mcp.NewToolResultText(fmt.Sprintf(
					"File read: %d bytes, %d files in directory", size, len(files),
				)), nil
			}
		}
		size := 0
		if sz, ok := result["size"].(int); ok {
			size = sz
		}
		return mcp.NewToolResultText(fmt.Sprintf("File read: %d bytes", size)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
