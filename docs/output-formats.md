# Output Formats

The MCP Scanner supports multiple output formats to suit different use cases and preferences:

## Available Formats

- **`raw`**: Raw JSON output with complete scan results
- **`summary`**: Concise summary showing only key findings
- **`detailed`**: Comprehensive output with full finding details
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
          "threat_names": ["SUSPICIOUS CODE EXECUTION"],
          "threat_summary": "Detected 1 threat: command injection",
          "total_findings": 1,
          "threats": {
            "items": [
              {
                "technique_id": "AITech-1.4",
                "technique_name": "Injection Attacks (SQL, Command Execution, XSS)",
                "items": [
                  {
                    "sub_technique_id": "AISubTech-1.4.1",
                    "sub_technique_name": "Injection Attacks (SQL, Command Execution, XSS)",
                    "max_severity": "HIGH",
                    "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment."
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
