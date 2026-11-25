# Behavioral Scanning

The Behavioral Code Analyzer is a source code analysis in MCP Scanner. It combines LLM-powered behavioral analysis with cross-file dataflow tracking, alignment checking to detect threats in MCP tools.

## Supported Languages

Python, TypeScript, JavaScript, Go, Java, Kotlin, C#, Rust, Ruby, PHP

## Overview

The Behavioral Analyzer uses advanced program analysis techniques combined with LLM intelligence to detect behavioral mismatches between what a function claims to do (via its docstring) and what it actually does (via its implementation).

## Quick Start

### Basic Usage

```bash
# Scan a single file (any supported language)
mcp-scanner behavioral /path/to/mcp_server.py
mcp-scanner behavioral /path/to/server.ts
mcp-scanner behavioral /path/to/server.go
mcp-scanner behavioral /path/to/McpService.java

# Scan a directory
mcp-scanner behavioral /path/to/mcp_servers/

# With specific output format
mcp-scanner behavioral /path/to/mcp_server.py --format by_severity

# Save results to file
mcp-scanner behavioral /path/to/mcp_server.py --output results.json
```

### Environment Setup

The Behavioral Analyzer requires an LLM provider (tested with Claude 4.5 Sonnet from Bedrock):

```bash

export AWS_PROFILE="your-profile"
export AWS_REGION="us-east-1"
export MCP_SCANNER_LLM_MODEL="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0"

# OpenAI
export MCP_SCANNER_LLM_API_KEY="sk-your-openai-api-key"
export MCP_SCANNER_LLM_MODEL="gpt-4o"

# Azure OpenAI
export MCP_SCANNER_LLM_API_KEY="your-azure-api-key"
export MCP_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export MCP_SCANNER_LLM_API_VERSION="2024-02-15-preview"
export MCP_SCANNER_LLM_MODEL="azure/gpt-4.1"

```

See [LLM Providers](llm-providers.md) for complete configuration options.

## Output Formats

The Behavioral Analyzer supports multiple output formats:

### Summary (Default)

```bash
mcp-scanner behavioral /path/to/server.py --format summary
```

Provides a high-level overview with counts of safe/unsafe tools and severity breakdown.

### Detailed

```bash
mcp-scanner behavioral /path/to/server.py --format detailed
```

Shows full threat summaries, line numbers, and detailed explanations for each finding.

### By Tool

```bash
mcp-scanner behavioral /path/to/server.py --format by_tool
```

Organizes results by tool name with visual indicators (🔴 for unsafe, 🟢 for safe).

### By Analyzer

```bash
mcp-scanner behavioral /path/to/server.py --format by_analyzer
```

Groups findings by analyzer with severity breakdown and statistics.

### By Severity

```bash
mcp-scanner behavioral /path/to/server.py --format by_severity
```

Organizes findings by severity level (HIGH, MEDIUM, LOW) for prioritization.

### Table

```bash
mcp-scanner behavioral /path/to/server.py --format table
```

Displays results in a tabular format with columns for tool name, status, and severity.

### Raw (JSON)

```bash
mcp-scanner behavioral /path/to/server.py --format raw
```

Outputs pure JSON for programmatic processing and integration.


### Static Analysis Components

#### 1. Parser Layer

- **PythonParser**: Parses Python source code into Abstract Syntax Trees (AST)
- **MCP Decorator Detection**: Identifies `@mcp.tool()` (and related) decorators on **`MCPServer`** (mcp 2.0) and legacy **`FastMCP`** server instances
- **Function Context Extraction**: Extracts parameters, return types, docstrings, and metadata

#### 2. Control Flow Analysis

- **CFG Builder**: Constructs Control Flow Graphs for each function
- **Node Types**: Entry, exit, conditional branches, loops, function calls
- **Edge Types**: Sequential flow, conditional branches, exception paths

#### 3. Dataflow Analysis

The analyzer implements multiple dataflow analysis:

**Forward Flow Tracking**
- Tracks how MCP entry point parameters flow through the code
- capture all function  parameters are involved
- Captures function calls, assignments, and returns
- No predefined "dangerous" operations - reports everything to LLM

**Constant Propagation**
- On-demand analysis (lazy evaluation)
- Sparse analysis (only relevant variables)
- Tracks literal values and symbolic expressions

**Reaching Definitions**
- Use-driven analysis (only compute what's needed)
- Tracks which definitions reach which uses
- Identifies parameter-influenced variables

**Liveness Analysis**
- Backward dataflow analysis
- Identifies live variables at each program point
- Detects dead code and unused assignments

#### 4. Taint Analysis

**TaintShape with Bounded Depth**
- Tracks tainted data structures (objects, arrays, nested structures)
- Maximum depth of 3 levels to prevent memory explosion
- Collapses deeper structures into summary nodes
- Efficient memory usage on complex nested data

**Taint Propagation Rules**
- Parameters are sources (untrusted input)
- Taint flows through assignments, function calls, returns
- Field access and array indexing preserve taint
- Merge operations combine taint from multiple paths

#### 5. Interprocedural Analysis

**Call Graph Construction**
- Builds complete call graph across all files
- Resolves imports and module dependencies
- Tracks MCP entry points and their callees

**Cross-File Dataflow**
- Follows function calls across file boundaries
- Tracks code flows through imported functions
- Maximum depth of 3 to prevent infinite recursion
- Reports all operations in called functions to LLM

### Alignment Checking

The alignment layer compares docstring claims against actual behavior:

#### 1. Prompt Building

Constructs structured prompts with:
- Function signature and docstring
- Complete dataflow information
- All operations performed
- Cross-file call information
- Control flow patterns

#### 2. LLM Analysis

The LLM evaluates:
- Does the code match the docstring description?
- Are there hidden operations not mentioned?
- Is data being exfiltrated?
- Are there injection vulnerabilities?
- Is the behavior malicious or suspicious?

#### 3. Response Validation

- JSON schema validation
- Required field checking
- Severity level validation
- Threat name extraction

#### 4. Taxonomy Mapping

Maps findings to Cisco MCP Threat taxonomy


See [MCP Threats Taxonomy](mcp-threats-taxonomy.md) for complete taxonomy.

## Performance Optimizations

The Behavioral Analyzer includes several optimizations for efficient analysis:

### 1. Bounded TaintShape

- Maximum depth of 3 levels for nested structures
- Prevents exponential memory growth
- Collapses deep structures into summary nodes

### 2. On-Demand Constant Propagation

- Lazy evaluation (only when needed)
- Sparse analysis (only relevant variables)
- Skips unnecessary computations

### 3. Demand-Driven Dataflow

- Use-driven reaching definitions
- Only computes what's actually used
- Avoids analyzing dead code

### 4. Function-Scoped CFG

- Builds CFG only for analyzed function
- Smaller graphs = faster analysis
- Reduces memory footprint

### 5. Bounded Interprocedural Analysis

- Maximum depth of 3 for cross-file tracking
- Prevents infinite recursion
- Tracks most important call chains

## Error Handling

The analyzer includes comprehensive error handling:

### Graceful Degradation

- Returns `<unknown>` for unparseable type annotations
- Returns `<complex>` for unparseable expressions
- Continues analysis on partial failures

### Specific Exception Handling

- `AttributeError`: Missing AST attributes
- `TypeError`: Type mismatches in analysis
- `ValueError`: Invalid values or formats
- `SyntaxError`: Malformed source code

### Logging

- Debug logs for skipped files
- Error logs for analysis failures
- Info logs for progress tracking

## Programmatic Usage

```python
import asyncio
import os

from mcpscanner import Config
from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer

# Configure LLM
config = Config(
    llm_provider_api_key="your-api-key",
    llm_model="gpt-4o",
    llm_temperature=0.1,
)

# Create the behavioral analyzer
analyzer = BehavioralCodeAnalyzer(config)

# analyze() treats a string that is not an existing file or directory as
# inline source code, so check the path first.
source_path = "/path/to/mcp_server.py"
if not os.path.exists(source_path):
    raise FileNotFoundError(source_path)

# Scan a file or directory. analyze() returns one SecurityFinding per MCP tool:
# severity "SAFE" when there is no mismatch, and "UNKNOWN" (with
# details["analysis_status"] == "errored") when the alignment check failed.
findings = asyncio.run(
    analyzer.analyze(source_path, context={"file_path": source_path})
)

# analyze() does not raise when a file cannot be read or parsed. It counts the
# failure in analysis_errors, so check it before trusting the results.
if analyzer.analysis_errors:
    raise RuntimeError(f"Scan incomplete: {analyzer.analysis_errors} analysis error(s)")

# An empty list means no MCP tool was found. It does not mean the code is safe.
if not findings:
    print("No MCP tools found")

# Process results. details["source_file"] tells apart tools with the same
# function name in different files of a directory scan.
for finding in findings:
    tool = f"{finding.details['source_file']}:{finding.details['function_name']}"
    if finding.details.get("analysis_status") == "errored":
        print(f"❓ {tool}: not analyzed ({finding.summary})")
    elif finding.severity != "SAFE":
        print(f"⚠️  {tool}: {finding.severity}")
        print(f"   {finding.summary}")
```

### Filtering Results

The helpers in `mcpscanner.core.result` work on scan result objects, so wrap the
finding of each tool in a `ToolScanResult` first. Give a tool whose analysis
errored a status other than `"completed"`, so it is reported as incomplete
instead of as a threat, and stays visible in every severity filter:

```python
from mcpscanner.core.result import ToolScanResult, filter_results_by_severity


def to_result(finding):
    details = finding.details
    errored = details.get("analysis_status") == "errored"
    return ToolScanResult(
        tool_name=f"{details['source_file']}:{details['function_name']}",
        tool_description="",
        status="failed" if errored else "completed",
        analyzers=[] if errored else [finding.analyzer],
        findings=[] if errored or finding.severity == "SAFE" else [finding],
        analyzer_errors=(
            [{"analyzer": finding.analyzer, "content_type": "source", "message": finding.summary}]
            if errored
            else []
        ),
    )


results = [to_result(finding) for finding in findings]

# Get only HIGH severity findings (plus tools whose analysis errored)
high_severity = filter_results_by_severity(results, "high")

# Get only MEDIUM severity findings (plus tools whose analysis errored)
medium_severity = filter_results_by_severity(results, "medium")
```

### Custom Output Formatting

```python
from mcpscanner.core.result import format_results_as_json, format_results_by_analyzer

# JSON output (takes the whole list)
json_output = format_results_as_json(results)

# Grouped by analyzer (takes one result at a time)
for result in results:
    print(format_results_by_analyzer(result))
```

## Best Practices

### 1. Use Appropriate Formats

- **summary**: Quick overview for CI/CD
- **by_severity**: Prioritize remediation
- **detailed**: Deep investigation
- **raw**: Programmatic processing

### 2. Optimize for Scale

- Scan directories in parallel (future feature)
- Use `--output` to save results
- Filter by severity for large codebases

### 3. Interpret Results

- HIGH severity: Immediate action required
- MEDIUM severity: Review and assess
- LOW severity: Monitor and track

### 4. False Positive Handling

- Review alignment mismatches carefully
- Consider legitimate use cases
- Provide feedback for model improvement

## Limitations

### Current Limitations

1. **Language Coverage**: Only files in the [supported languages](#supported-languages) are scanned
2. **LLM Dependency**: Requires LLM API access and credits
3. **Analysis Time**: Slower than pattern-based approaches
4. **Dynamic Behavior**: Cannot detect runtime-only behaviors
5. **Obfuscation**: May miss heavily obfuscated code

### Future Enhancements

- Integration with static analysis tools

### Debug Mode

```bash
# Enable verbose logging
mcp-scanner behavioral /path/to/server.py --verbose

# Save debug output
mcp-scanner behavioral /path/to/server.py --verbose > debug.log 2>&1
```

## Related Documentation

- [Architecture](architecture.md): Overall system architecture
- [LLM Providers](llm-providers.md): LLM configuration guide
- [MCP Threats Taxonomy](mcp-threats-taxonomy.md): Complete threat taxonomy
- [Output Formats](output-formats.md): Detailed format specifications
- [API Reference](api-reference.md): Programmatic API documentation

## Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/cisco-ai-defense/mcp-scanner/issues
- Documentation: https://github.com/cisco-ai-defense/mcp-scanner/tree/main/docs
