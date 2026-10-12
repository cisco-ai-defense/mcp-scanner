// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Format-string style tar/rsync command construction executed via bash -c (Cf. Python % formatting).

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type BackupManager struct{}

const backupDir = "/var/backups"

func (BackupManager) generateBackupName(source, formatType string) string {
	ts := time.Now().Format("20060102_150405")
	base := path.Base(source)
	return fmt.Sprintf("%s_%s.%s", base, ts, formatType)
}

func (BackupManager) createTarBackup(source, destination, compression string) int {
	compressionFlags := map[string]string{
		"gzip":  "-czf",
		"bzip2": "-cjf",
		"xz":    "-cJf",
		"none":  "-cf",
	}
	flags := compressionFlags["gzip"]
	if v, ok := compressionFlags[compression]; ok {
		flags = v
	}
	// VULNERABLE: Sprintf-derived command string handed to shell
	command := fmt.Sprintf("tar %s %s %s", flags, destination, source)
	return runShell(command)
}

func (BackupManager) createRsyncBackup(source, destination string, excludes []string) int {
	excl := ""
	for _, pattern := range excludes {
		excl += fmt.Sprintf(" --exclude='%s'", pattern)
	}
	command := fmt.Sprintf("rsync -av%s %s %s", excl, source, destination)
	return runShell(command)
}

func runShell(cmd string) int {
	c := exec.Command("bash", "-c", cmd)
	err := c.Run()
	if err == nil {
		return 0
	}
	if ex, ok := err.(*exec.ExitError); ok {
		return ex.ExitCode()
	}
	return 1
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-8", "1.0.0")

	tool := mcp.NewTool("create_backup",
		mcp.WithDescription("Create backup of specified directory with flexible options."),
		mcp.WithString("directory", mcp.Required()),
		mcp.WithString("backup_type"),
		mcp.WithString("compression"),
		mcp.WithString("destination"),
		mcp.WithString("exclude_patterns"),
		mcp.WithString("custom_flags"),
	)

	var mgr BackupManager
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		dir := req.GetString("directory", "")
		btype := req.GetString("backup_type", "tar")
		comp := req.GetString("compression", "gzip")
		dest := req.GetString("destination", "")
		exPatterns := req.GetString("exclude_patterns", "")
		custom := req.GetString("custom_flags", "")

		if dest == "" {
			dest = path.Join(backupDir, mgr.generateBackupName(dir, "tar.gz"))
		}

		var excludes []string
		if exPatterns != "" {
			for _, p := range strings.Split(exPatterns, ",") {
				excludes = append(excludes, strings.TrimSpace(p))
			}
		}

		var rc int
		switch btype {
		case "rsync":
			rc = mgr.createRsyncBackup(dir, dest, excludes)
		default:
			if custom != "" {
				command := fmt.Sprintf("%s %s %s %s", custom, comp, dest, dir)
				rc = runShell(command)
			} else {
				rc = mgr.createTarBackup(dir, dest, comp)
			}
		}

		if rc == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("Backup created successfully: %s", dest)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Backup failed with exit code: %d", rc)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
