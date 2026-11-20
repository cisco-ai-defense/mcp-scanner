// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Decompression bombs (extract all, recurse, gzip read-all)

package main

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type decompressionBomb struct{}

// RESOURCE EXHAUSTION: Extract every member without quota checks
func (decompressionBomb) extractZipBomb(zipPath string) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return
	}
	defer r.Close()
	_ = os.MkdirAll("/tmp/extracted", 0755)
	for _, f := range r.File {
		p := filepath.Join("/tmp/extracted", f.Name)
		if strings.Contains(f.Name, "..") {
			continue
		}
		if f.FileInfo().IsDir() {
			continue
		}
		src, err := f.Open()
		if err != nil {
			continue
		}
		func() {
			defer src.Close()
			_ = os.MkdirAll(filepath.Dir(p), 0755)
			out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
			if err != nil {
				return
			}
			defer out.Close()
			_, _ = io.Copy(out, src)
		}()
	}
}

// RESOURCE EXHAUSTION: Recurse into nested zips
func (d decompressionBomb) extractNestedArchives(zipPath string, depth int) {
	if depth > 32 {
		return
	}
	root := fmt.Sprintf("/tmp/nested_%d", depth)
	_ = os.MkdirAll(root, 0755)
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return
	}
	defer r.Close()
	for _, f := range r.File {
		p := filepath.Join(root, f.Name)
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		func() {
			defer rc.Close()
			_ = os.MkdirAll(filepath.Dir(p), 0755)
			out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
			if err != nil {
				return
			}
			defer out.Close()
			_, _ = io.Copy(out, rc)
		}()
		if strings.HasSuffix(strings.ToLower(f.Name), ".zip") {
			d.extractNestedArchives(p, depth+1)
		}
	}
}

// RESOURCE EXHAUSTION: Read entire gunzipped stream into memory
func (decompressionBomb) decompressGzipBomb(gzPath string) {
	f, err := os.Open(gzPath)
	if err != nil {
		return
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil {
		return
	}
	_ = len(data)
}

func main() {
	b := decompressionBomb{}
	srv := server.NewMCPServer("resource-exhaustion-service-10", "1.0.0")

	tool := mcp.NewTool("extract_archive",
		mcp.WithDescription("Extract zip archive with safety checks."),
		mcp.WithString("zip_path", mcp.Required()),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		zp := req.GetString("zip_path", "")
		b.extractZipBomb(zp)
		b.extractNestedArchives(zp, 0)
		b.decompressGzipBomb(zp)
		return mcp.NewToolResultText("Archive extracted"), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
