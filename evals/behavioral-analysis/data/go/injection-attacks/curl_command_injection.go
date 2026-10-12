// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Curl / shell injection — concatenated curl command passed to bash -c.

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

type HTTPClient struct{}

func (HTTPClient) validateURL(url string) bool {
	ok, _ := regexp.MatchString(`^https?://`, url)
	return ok
}

func (HTTPClient) buildCurlCommand(url, method string, headers map[string]string, data, outputFile string, followRedirects bool, customOptions string) string {
	cmdParts := []string{"curl"}

	if method != "GET" && method != "" {
		cmdParts = append(cmdParts, "-X "+method)
	}

	for k, v := range headers {
		cmdParts = append(cmdParts, fmt.Sprintf("-H '%s: %s'", k, v))
	}

	if data != "" {
		cmdParts = append(cmdParts, fmt.Sprintf("-d '%s'", data))
	}

	if outputFile != "" {
		cmdParts = append(cmdParts, "-o "+outputFile)
	}

	if followRedirects {
		cmdParts = append(cmdParts, "-L")
	}

	if customOptions != "" {
		cmdParts = append(cmdParts, customOptions)
	}

	cmdParts = append(cmdParts, url)
	return strings.Join(cmdParts, " ")
}

func (HTTPClient) executeCurl(command string, timeoutSecs int) (stdout, stderr string, rc int) {
	c := exec.Command("bash", "-c", command)
	out, err := c.CombinedOutput()
	stdout = string(out)
	if err != nil {
		rc = 1
		stderr = err.Error()
		if ex, ok := err.(*exec.ExitError); ok {
			rc = ex.ExitCode()
		}
	}
	return
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-10", "1.0.0")

	tool := mcp.NewTool("fetch_url",
		mcp.WithDescription("Fetch content from URL using curl with flexible HTTP options."),
		mcp.WithString("url", mcp.Required()),
		mcp.WithString("method"),
		mcp.WithString("headers"),
		mcp.WithString("post_data"),
		mcp.WithString("output_file"),
		mcp.WithString("custom_options"),
		mcp.WithBoolean("follow_redirects"),
	)

	var client HTTPClient
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		u := req.GetString("url", "")
		if !client.validateURL(u) {
			return mcp.NewToolResultText("Invalid URL format"), nil
		}

		headerDict := map[string]string{}
		if hdrs := req.GetString("headers", ""); hdrs != "" {
			for _, header := range strings.Split(hdrs, ";") {
				if strings.Contains(header, ":") {
					parts := strings.SplitN(header, ":", 2)
					headerDict[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}

		cmdStr := client.buildCurlCommand(
			u,
			req.GetString("method", "GET"),
			headerDict,
			req.GetString("post_data", ""),
			req.GetString("output_file", ""),
			req.GetBool("follow_redirects", true),
			req.GetString("custom_options", ""),
		)

		stdout, stderr, rc := client.executeCurl(cmdStr, 30)

		if rc == 0 {
			if req.GetString("output_file", "") != "" {
				return mcp.NewToolResultText("Content saved to: " + req.GetString("output_file", "")), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("Content fetched: %d bytes", len(stdout))), nil
		}
		se := stderr
		if len(se) > 200 {
			se = se[:200]
		}
		return mcp.NewToolResultText("Request failed: " + se), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
