# Output Formats

The MCP Scanner supports multiple output formats to suit different use cases and preferences:

## Available Formats

- **`raw`**: Raw JSON output with complete scan results including hierarchical MCP taxonomy
- **`summary`**: Concise summary showing only key findings
- **`detailed`**: Comprehensive output with full finding details and MCP taxonomy information
- **`by_tool`**: Results grouped by scanned tool
- **`by_analyzer`**: Results grouped by analyzer type (API, YARA, LLM)
- **`by_severity`**: Results grouped by severity level (HIGH, MEDIUM, LOW, UNKNOWN)
- **`table`**: Tabular format for easy reading

## Format Examples

### Summary Format
```bash
 mcp-scanner --server-url http://127.0.0.1:8001/sse --format summary
```
Shows a concise overview with tool names, overall status, and highest severity findings.

### Detailed Format
```bash
mcp-scanner --server-url http://127.0.0.1:8001/sse --format detailed
```
Provides comprehensive output with full finding details, including hierarchical MCP taxonomy information for all analyzers. Shows multiple taxonomies when a tool matches different threat types.

### By Severity Format
```bash
mcp-scanner --server-url http://127.0.0.1:8001/sse --format by_severity
```
Groups all findings by severity level, making it easy to prioritize security issues.

### Table Format
```bash
mcp-scanner --server-url http://127.0.0.1:8001/sse --format table
```
Displays results in a clean tabular format with columns for tool, analyzer, severity, and findings.

## Filtering Options

### Severity Filtering
```bash
# Show only high severity findings
mcp-scanner --server-url http://127.0.0.1:8001/sse --severity-filter high

# Show high and medium severity findings
mcp-scanner --server-url http://127.0.0.1:8001/sse --severity-filter high,medium

# Available severity levels: high, medium, low, unknown
```

### Analyzer Filtering
```bash
# Show only YARA analyzer results
mcp-scanner --server-url http://127.0.0.1:8001/sse --analyzer-filter yara_analyzer

# Show API and LLM analyzer results
mcp-scanner --server-url http://127.0.0.1:8001/sse --analyzer-filter api_analyzer,llm_analyzer

# Available analyzers: api_analyzer, yara_analyzer, llm_analyzer
```

### Additional Options
```bash
# Hide tools with no security findings
mcp-scanner --server-url http://127.0.0.1:8001/sse --hide-safe

# Show scan statistics (total tools, vulnerable tools, etc.)
mcp-scanner --server-url http://127.0.0.1:8001/sse --stats

# Combine multiple options
mcp-scanner --server-url http://127.0.0.1:8001/sse --format by_severity --severity-filter high,medium --stats
```

## Example Output

### Raw Format
```json
{
  "server_url": "http://127.0.0.1:8001/sse",
  "scan_results": [
    {
      "tool_name": "execute_command",
      "tool_description": "Execute shell commands",
      "status": "completed",
      "is_safe": false,
      "findings": {
        "yara_analyzer": {
          "severity": "HIGH",
          "total_findings": 1,
          "threats": {
            "items": [
              {
                "technique_id": "AITech-9.1",
                "technique_name": "Model or Agentic System Manipulation",
                "items": [
                  {
                    "sub_technique_id": "AISubtech-9.1.1",
                    "sub_technique_name": "Code Execution",
                    "max_severity": "HIGH",
                    "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components."
                  }
                ]
              }
            ]
          }
        }
      }
    }
  ]
}
```

### Detailed Format Example
```
Tool 1: malicious_tool
Status: completed
Safe: No
Analyzer Results:
  • llm_analyzer:
    - Severity: HIGH
    - Threat Summary: Detected 2 threats: data exfiltration, prompt injection
    - Threat Names: DATA EXFILTRATION, PROMPT INJECTION
    - Total Findings: 2
    - MCP Taxonomies (2 unique threats):
      [1] Data Exfiltration / Exposure
          • AITech: AITech-8.2
          • AISubtech: AISubtech-8.2.3
          • AISubtech Name: Data Exfiltration via Agent Tooling
          • Description: Unintentional and/or unauthorized exposure or exfiltration...
      [2] Direct Prompt Injection
          • AITech: AITech-1.1
          • AISubtech: AISubtech-1.1.1
          • AISubtech Name: Instruction Manipulation (Direct Prompt Injection)
          • Description: Explicit attempts to override, replace, or modify...
```

### Summary Format
```
=== MCP Scanner Results ===

Server: http://127.0.0.1:8001/sse
Tools Scanned: 3
Safe Tools: 2
Unsafe Tools: 1

High Priority Issues:
• execute_command - YARA: Command injection patterns detected
```

### Table Format
```
┌─────────────────┬──────────────┬──────────┬────────────────────────────────┐
│ Tool Name       │ Analyzer     │ Severity │ Findings                       │
├─────────────────┼──────────────┼──────────┼────────────────────────────────┤
│ execute_command │ YARA         │ HIGH     │ Command injection patterns     │
│ safe_calculator │ All          │ SAFE     │ No issues found                │
│ file_reader     │ API          │ MEDIUM   │ Potential data exfiltration    │
└─────────────────┴──────────────┴──────────┴────────────────────────────────┘
```
