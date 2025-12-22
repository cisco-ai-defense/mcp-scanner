# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for TypeScript context extractor."""

import pytest

from mcpscanner.core.static_analysis.typescript_context_extractor import (
    TypeScriptContextExtractor,
    TypeScriptFunctionContext,
)


class TestTypeScriptContextExtractor:
    """Test TypeScript context extractor functionality."""

    def test_extract_mcp_tool_registration(self):
        """Test extracting context from MCP tool registration."""
        source = """
import { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod';

const server = new McpServer({
    name: 'test-server',
    version: '1.0.0'
});

server.registerTool(
    'read-file',
    {
        description: 'Read a file from disk',
        inputSchema: {
            path: z.string().describe('File path to read')
        }
    },
    async ({ path }) => {
        const fs = require('fs');
        const content = fs.readFileSync(path, 'utf-8');
        return {
            content: [{ type: 'text', text: content }]
        };
    }
);
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        # Should find the tool handler
        assert len(contexts) >= 1
        
        # Check for file operations detection
        tool_context = contexts[0]
        assert tool_context.has_file_operations

    def test_extract_arrow_function_handler(self):
        """Test extracting context from arrow function handlers."""
        source = """
const server = new McpServer({ name: 'test', version: '1.0.0' });

server.tool('greet', { name: z.string() }, async ({ name }) => {
    console.log(`Greeting ${name}`);
    return { content: [{ type: 'text', text: `Hello, ${name}!` }] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        assert len(contexts) >= 1

    def test_detect_network_operations(self):
        """Test detection of network operations."""
        source = """
server.registerTool('fetch-data', {}, async ({ url }) => {
    const response = await fetch(url);
    const data = await response.json();
    return { content: [{ type: 'text', text: JSON.stringify(data) }] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        if contexts:
            assert contexts[0].has_network_operations

    def test_detect_subprocess_calls(self):
        """Test detection of subprocess/exec calls."""
        source = """
import { exec } from 'child_process';

server.registerTool('run-command', {}, async ({ command }) => {
    return new Promise((resolve) => {
        exec(command, (error, stdout, stderr) => {
            resolve({ content: [{ type: 'text', text: stdout }] });
        });
    });
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        if contexts:
            assert contexts[0].has_subprocess_calls

    def test_detect_eval_usage(self):
        """Test detection of eval/Function usage."""
        source = """
server.registerTool('evaluate', {}, async ({ code }) => {
    const result = eval(code);
    return { content: [{ type: 'text', text: String(result) }] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        if contexts:
            assert contexts[0].has_eval_exec

    def test_extract_imports(self):
        """Test extraction of imports."""
        source = """
import { readFile } from 'fs/promises';
import * as path from 'path';
import express from 'express';

server.registerTool('test', {}, async () => {
    return { content: [] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        # Check that imports are extracted at file level
        if contexts:
            imports = contexts[0].imports
            assert len(imports) >= 3

    def test_extract_function_calls(self):
        """Test extraction of function calls within handler."""
        source = """
server.registerTool('process', {}, async ({ data }) => {
    const parsed = JSON.parse(data);
    const result = processData(parsed);
    console.log('Processed:', result);
    return { content: [{ type: 'text', text: result }] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        if contexts:
            calls = contexts[0].function_calls
            call_names = [c['name'] for c in calls]
            assert 'JSON.parse' in call_names or 'console.log' in call_names

    def test_extract_string_literals(self):
        """Test extraction of string literals."""
        source = """
server.registerTool('connect', {}, async () => {
    const url = "https://api.example.com/v1";
    const secret = "sk-secret-key-12345";
    return { content: [{ type: 'text', text: 'Connected' }] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        if contexts:
            literals = contexts[0].string_literals
            assert any("api.example.com" in s for s in literals)

    def test_extract_env_var_access(self):
        """Test extraction of environment variable access."""
        source = """
server.registerTool('get-config', {}, async () => {
    const apiKey = process.env.API_KEY;
    const dbUrl = process.env.DATABASE_URL;
    return { content: [{ type: 'text', text: 'Config loaded' }] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        if contexts:
            env_vars = contexts[0].env_var_access
            assert 'API_KEY' in env_vars or 'DATABASE_URL' in env_vars

    def test_control_flow_analysis(self):
        """Test control flow analysis."""
        source = """
server.registerTool('conditional', {}, async ({ value }) => {
    if (value > 10) {
        for (let i = 0; i < value; i++) {
            console.log(i);
        }
    } else {
        while (value < 10) {
            value++;
        }
    }
    
    try {
        riskyOperation();
    } catch (e) {
        console.error(e);
    }
    
    return { content: [] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        if contexts:
            cf = contexts[0].control_flow
            assert cf['has_conditionals']
            assert cf['has_loops']
            assert cf['has_exception_handling']

    def test_dataflow_summary(self):
        """Test dataflow summary generation."""
        source = """
server.registerTool('complex', {}, async ({ input }) => {
    const a = input.trim();
    const b = a.toLowerCase();
    const c = b.split(' ');
    if (c.length > 0) {
        return { content: [{ type: 'text', text: c.join('-') }] };
    }
    return { content: [] };
});
"""
        extractor = TypeScriptContextExtractor(source, "test.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        if contexts:
            summary = contexts[0].dataflow_summary
            assert 'total_statements' in summary
            assert 'complexity' in summary
            assert summary['complexity'] >= 1

    def test_real_mcp_server_example(self):
        """Test with real MCP server code pattern."""
        source = """
import type { CallToolResult } from '@modelcontextprotocol/server';
import { createMcpExpressApp, McpServer, SSEServerTransport } from '@modelcontextprotocol/server';
import type { Request, Response } from 'express';
import * as z from 'zod/v4';

const getServer = () => {
    const server = new McpServer(
        {
            name: 'simple-sse-server',
            version: '1.0.0'
        },
        { capabilities: { logging: {} } }
    );

    server.registerTool(
        'start-notification-stream',
        {
            description: 'Starts sending periodic notifications',
            inputSchema: {
                interval: z.number().describe('Interval in milliseconds').default(1000),
                count: z.number().describe('Number of notifications').default(10)
            }
        },
        async ({ interval, count }, extra): Promise<CallToolResult> => {
            const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
            let counter = 0;

            await server.sendLoggingMessage(
                {
                    level: 'info',
                    data: `Starting notification stream with ${count} messages every ${interval}ms`
                },
                extra.sessionId
            );

            while (counter < count) {
                counter++;
                await sleep(interval);
                await server.sendLoggingMessage(
                    {
                        level: 'info',
                        data: `Notification #${counter} at ${new Date().toISOString()}`
                    },
                    extra.sessionId
                );
            }

            return {
                content: [
                    {
                        type: 'text',
                        text: `Completed sending ${count} notifications every ${interval}ms`
                    }
                ]
            };
        }
    );
    return server;
};
"""
        extractor = TypeScriptContextExtractor(source, "server.ts")
        contexts = extractor.extract_mcp_function_contexts()
        
        # Should extract the tool handler
        assert len(contexts) >= 1
        
        # Verify context properties
        context = contexts[0]
        assert context.control_flow['has_loops']  # while loop
        assert len(context.function_calls) > 0  # Multiple function calls
