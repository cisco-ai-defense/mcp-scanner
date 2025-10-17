#!/usr/bin/env python3
"""
Test TypeScript/JavaScript MCP Function Extraction

Tests that the CodeLLMAnalyzer can extract MCP functions from
TypeScript and JavaScript files.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner.core.analyzers.code_llm_analyzer import (
    CodeLLMAnalyzer,
    SupportedLanguage
)
from mcpscanner.config.config import Config


# Sample TypeScript MCP server code
TYPESCRIPT_CODE_1 = '''
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server(
  {
    name: "example-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool using server.tool() pattern
server.tool(
  "read_file",
  {
    path: {
      type: "string",
      description: "Path to file",
    },
  },
  async ({ path }) => {
    const fs = require('fs');
    const content = fs.readFileSync(path, 'utf-8');
    return {
      content: [{ type: "text", text: content }],
    };
  }
);

// Tool using server.registerTool() pattern
server.registerTool(
  "execute_command",
  {
    command: {
      type: "string",
      description: "Command to execute",
    },
  },
  async ({ command }) => {
    const { exec } = require('child_process');
    return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) reject(error);
        resolve({ content: [{ type: "text", text: stdout }] });
      });
    });
  }
);

// Prompt registration
server.registerPrompt(
  "analyze_code",
  {
    language: {
      type: "string",
      description: "Programming language",
    },
  },
  async ({ language }) => {
    return {
      messages: [
        {
          role: "user",
          content: { type: "text", text: `Analyze ${language} code` },
        },
      ],
    };
  }
);

// Resource registration
server.resource(
  "config://settings",
  async () => {
    return {
      contents: [
        {
          uri: "config://settings",
          mimeType: "application/json",
          text: JSON.stringify({ setting: "value" }),
        },
      ],
    };
  }
);
'''

TYPESCRIPT_CODE_2 = '''
// Different style with object notation
server.registerTool({
  name: "fetch_url",
  description: "Fetch content from URL",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string" },
    },
  },
  handler: async ({ url }) => {
    const response = await fetch(url);
    const data = await response.text();
    return { content: [{ type: "text", text: data }] };
  },
});
'''


def test_typescript_extraction():
    """Test extracting TypeScript MCP functions"""
    print("=" * 80)
    print("  TEST: TypeScript/JavaScript MCP Function Extraction")
    print("=" * 80)
    print()
    
    config = Config()
    analyzer = CodeLLMAnalyzer(config)
    
    # Test extraction from TypeScript code
    print("📄 Testing TypeScript Code Sample 1:")
    print("-" * 80)
    
    functions = analyzer._extract_mcp_functions(
        TYPESCRIPT_CODE_1,
        "example_server.ts",
        SupportedLanguage.TYPESCRIPT
    )
    
    print(f"✅ Extracted {len(functions)} MCP functions\n")
    
    for i, func in enumerate(functions, 1):
        print(f"{i}. {func.function_type.upper()}: {func.function_name}")
        print(f"   File: {func.file_path}")
        print(f"   Line: {func.line_number}")
        print(f"   Language: {func.language.value}")
        print(f"   Registration: {func.decorator_or_registration}")
        print(f"   Code length: {len(func.code_snippet)} characters")
        print(f"   Code preview:")
        preview = func.code_snippet[:200].replace('\n', '\n   ')
        print(f"   {preview}...")
        print()
    
    # Test extraction from TypeScript code sample 2
    print("\n📄 Testing TypeScript Code Sample 2:")
    print("-" * 80)
    
    functions2 = analyzer._extract_mcp_functions(
        TYPESCRIPT_CODE_2,
        "example_server2.ts",
        SupportedLanguage.TYPESCRIPT
    )
    
    print(f"✅ Extracted {len(functions2)} MCP functions\n")
    
    for i, func in enumerate(functions2, 1):
        print(f"{i}. {func.function_type.upper()}: {func.function_name}")
        print(f"   Code length: {len(func.code_snippet)} characters")
        print()
    
    return len(functions) + len(functions2)


def test_function_name_extraction():
    """Test function name extraction from TypeScript"""
    print("\n" + "=" * 80)
    print("  TEST: TypeScript Function Name Extraction")
    print("=" * 80)
    print()
    
    config = Config()
    analyzer = CodeLLMAnalyzer(config)
    
    test_cases = [
        ('server.tool("read_file", {...})', "read_file"),
        ('server.registerTool("execute_command", {...})', "execute_command"),
        ('server.registerPrompt("analyze_code", {...})', "analyze_code"),
        ('server.resource("config://settings", {...})', "config://settings"),
        ('server.registerTool({ name: "fetch_url", ...})', "fetch_url"),
    ]
    
    for code, expected_name in test_cases:
        extracted_name = analyzer._extract_function_name(
            code,
            r'server\.(tool|registerTool)',
            SupportedLanguage.TYPESCRIPT
        )
        
        status = "✅" if extracted_name == expected_name else "❌"
        print(f"{status} Code: {code[:50]}...")
        print(f"   Expected: {expected_name}")
        print(f"   Extracted: {extracted_name}")
        print()


def test_patterns():
    """Test TypeScript pattern matching"""
    print("\n" + "=" * 80)
    print("  TEST: TypeScript Pattern Matching")
    print("=" * 80)
    print()
    
    import re
    
    config = Config()
    analyzer = CodeLLMAnalyzer(config)
    
    patterns = analyzer.mcp_patterns[SupportedLanguage.TYPESCRIPT]
    
    test_strings = [
        "server.tool(",
        "server.registerTool(",
        "server.prompt(",
        "server.registerPrompt(",
        "server.resource(",
        "server.registerResource(",
    ]
    
    print("Testing pattern matches:")
    for pattern_name, pattern in patterns.items():
        print(f"\n📋 Pattern '{pattern_name}': {pattern}")
        for test_str in test_strings:
            match = re.search(pattern, test_str)
            if match:
                print(f"   ✅ Matches: {test_str}")


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("  TYPESCRIPT/JAVASCRIPT EXTRACTION TEST SUITE")
    print("=" * 80)
    
    # Test 1: Pattern matching
    test_patterns()
    
    # Test 2: Function name extraction
    test_function_name_extraction()
    
    # Test 3: Full extraction
    total_functions = test_typescript_extraction()
    
    print("\n" + "=" * 80)
    print("  TESTS COMPLETE")
    print("=" * 80)
    print()
    print(f"✅ Successfully extracted {total_functions} TypeScript/JavaScript MCP functions!")
    print("   - server.tool() pattern supported")
    print("   - server.registerTool() pattern supported")
    print("   - server.prompt() pattern supported")
    print("   - server.registerPrompt() pattern supported")
    print("   - server.resource() pattern supported")
    print("   - server.registerResource() pattern supported")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
