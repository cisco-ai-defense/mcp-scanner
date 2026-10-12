// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Templated shell command assembly (Template-style substitution + bash -c) mirroring Python.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var scriptTemplates = map[string]string{
	"convert": "convert $input_file $options $output_file",
	"process": "$processor -i $input_file -o $output_file $flags",
	"analyze": "$analyzer --input=$input_file --format=$format $extra_args",
	"custom":  "$command",
}

type FileProcessor struct{}

func (FileProcessor) buildCommand(templateName string, vars map[string]string) string {
	tmpl := scriptTemplates[templateName]
	if tmpl == "" {
		tmpl = scriptTemplates["custom"]
	}
	subRe := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)|\$\{([^}]+)\}`)
	tryStrict := func() (string, bool) {
		hasMissing := false
		out := subRe.ReplaceAllStringFunc(tmpl, func(orig string) string {
			sub := subRe.FindStringSubmatch(orig)
			key := sub[1]
			if key == "" {
				key = strings.TrimSpace(sub[2])
			}
			if v, hit := vars[key]; hit {
				return v
			}
			hasMissing = true
			return orig
		})
		if hasMissing {
			return "", false
		}
		return out, true
	}
	if out, ok := tryStrict(); ok {
		return out
	}
	return subRe.ReplaceAllStringFunc(tmpl, func(orig string) string {
		sub := subRe.FindStringSubmatch(orig)
		key := sub[1]
		if key == "" {
			key = strings.TrimSpace(sub[2])
		}
		if v, hit := vars[key]; hit {
			return v
		}
		return orig
	})
}

func (FileProcessor) execute(command string) map[string]any {
	cmd := exec.Command("bash", "-c", command)
	out, err := cmd.CombinedOutput()
	rc := 0
	stderr := ""
	if err != nil {
		stderr = err.Error()
		if ex, ok := err.(*exec.ExitError); ok {
			rc = ex.ExitCode()
		} else {
			rc = 1
		}
	}
	return map[string]any{"stdout": string(out), "stderr": stderr, "returncode": rc}
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-9", "1.0.0")

	tool := mcp.NewTool("process_file",
		mcp.WithDescription("Process file with custom script using templated commands."),
		mcp.WithString("filepath", mcp.Required()),
		mcp.WithString("processor"),
		mcp.WithString("template_name"),
		mcp.WithString("output_file"),
		mcp.WithString("options"),
		mcp.WithString("extra_args"),
	)

	var fp FileProcessor

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path := req.GetString("filepath", "")
		processor := req.GetString("processor", "cat")
		tmplName := req.GetString("template_name", "process")
		output := req.GetString("output_file", "")
		opts := req.GetString("options", "")
		extra := req.GetString("extra_args", "")

		if output == "" {
			output = path + ".processed"
		}

		variables := map[string]string{
			"input_file":  path,
			"output_file": output,
			"processor":   processor,
			"command":     processor,
			"options":     opts,
			"flags":       opts,
			"extra_args":  extra,
			"format":      "json",
			"analyzer":    processor,
		}

		command := fp.buildCommand(tmplName, variables)
		res := fp.execute(command)
		rc := res["returncode"].(int)

		if rc == 0 {
			c := command
			if len(c) > 100 {
				c = c[:100]
			}
			return mcp.NewToolResultText(fmt.Sprintf("Processing complete. Command executed: %s...",
				c)), nil
		}
		se := fmt.Sprintf("%v", res["stderr"])
		if len(se) > 200 {
			se = se[:200]
		}
		return mcp.NewToolResultText(fmt.Sprintf("Processing failed: %s", se)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
