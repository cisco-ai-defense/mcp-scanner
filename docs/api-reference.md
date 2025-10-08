# API Reference

The MCP Scanner API includes a REST API server built with FastAPI that allows you to expose the scanning functionality as a web service.

## Configuration

The API server uses a `.env` file for configuration. Create a `.env` file in your project directory with the following variables:

```
# Cisco AI Defense API Key (required)
MCP_SCANNER_API_KEY=your_api_key_here

# API Endpoint URL - defaults to US production if not specified
MCP_SCANNER_ENDPOINT="https://us.api.inspect.aidefense.security.cisco.com/api/v1"

Other Cisco AI Defense endpoints are documented at https://developer.cisco.com/docs/ai-defense/getting-started/#base-url 

```

You can also use environment variables instead of a `.env` file.

## API Endpoints

The MCP Scanner API supports all the same output formatting options as the CLI tool, allowing you to customize the response format and filtering.

### Available Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `server_url` | string | required | URL of the MCP server to scan |
| `analyzers` | array | ["yara"] | List of analyzers to use: "api", "yara", "llm" |
| `output_format` | string | "raw" | Output format (see formats below) |
| `severity_filter` | string | "all" | Filter by severity level |
| `analyzer_filter` | string | null | Filter by specific analyzer name |
| `tool_filter` | string | null | Filter by tool names |
| `hide_safe` | boolean | false | Hide tools with no security findings |
| `show_stats` | boolean | false | Include scan statistics |
| `rules_path` | string | null | Custom YARA rules directory path |
| `tool_name` | string | null | Specific tool name (scan-tool endpoint only) |

### Output Formats

- **`raw`** - Original structured JSON format (default)
- **`summary`** - Concise overview with key findings
- **`detailed`** - Comprehensive output with full details
- **`by_tool`** - Results grouped by tool name
- **`by_analyzer`** - Results grouped by analyzer type
- **`by_severity`** - Results grouped by severity level
- **`table`** - Clean tabular format

### Severity Filters

- **`all`** - Show all findings (default)
- **`high`** - Show only high severity findings
- **`medium`** - Show only medium severity findings
- **`low`** - Show only low severity findings
- **`safe`** - Show only safe tools

## Basic Examples

**Scan a Specific Tool:**
```bash
curl -X POST "http://localhost:8001/scan-tool" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "server_url": "https://mcp-server.example.com/mcp",
    "analyzers": ["api", "yara", "llm"],
    "output_format": "raw",
    "severity_filter": "all",
    "analyzer_filter": null,
    "tool_filter": null,
    "hide_safe": false,
    "show_stats": false,
    "rules_path": null,
    "tool_name": "add"
  }'
```

**Scan All Tools:**
```bash
curl -X POST "http://localhost:8001/scan-all-tools" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "server_url": "https://mcp-server.example.com/mcp",
    "analyzers": ["api", "yara", "llm"],
    "output_format": "raw",
    "severity_filter": "all",
    "analyzer_filter": null,
    "tool_filter": null,
    "hide_safe": false,
    "show_stats": false,
    "rules_path": null
  }'
```

## Advanced Output Format Examples

**Summary Format with Statistics:**
```bash
curl -X POST "http://localhost:8001/scan-all-tools" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "server_url": "https://mcp-server.example.com/mcp",
    "analyzers": ["api", "llm"],
    "output_format": "summary",
    "severity_filter": "all",
    "analyzer_filter": null,
    "tool_filter": null,
    "hide_safe": false,
    "show_stats": true,
    "rules_path": null
  }'
```

**High Severity Only in Table Format:**
```bash
curl -X POST "http://localhost:8001/scan-all-tools" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "server_url": "https://mcp-server.example.com/mcp",
    "analyzers": ["api", "yara", "llm"],
    "output_format": "table",
    "severity_filter": "high",
    "analyzer_filter": null,
    "tool_filter": null,
    "hide_safe": true,
    "show_stats": false,
    "rules_path": null
  }'
```

**Results Grouped by Severity:**
```bash
curl -X POST "http://localhost:8001/scan-all-tools" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "server_url": "https://mcp-server.example.com/mcp", 
    "authtoken": ""
    "analyzers": ["api", "llm"],
    "output_format": "by_severity",
    "severity_filter": "all",
    "analyzer_filter": null,
    "tool_filter": null,
    "hide_safe": false,
    "show_stats": false,
    "rules_path": null
  }'
```

## Response Structure

**Raw Format Response:**
```json
{
  "server_url": "https://mcp-server.example.com/mcp",
  "scan_results": [
    {
      "tool_name": "add",
      "status": "completed",
      "findings": {
        "api_analyzer": {
          "severity": "HIGH",
          "threat_names": ["SECURITY VIOLATION"],
          "threat_summary": "Detected 1 threat: security violation",
          "total_findings": 1
        },
        "yara_analyzer": {
          "severity": "HIGH",
          "threat_names": ["SECURITY VIOLATION", "SUSPICIOUS CODE EXECUTION"],
          "threat_summary": "Detected 2 threat: system access, script injection",
          "total_findings": 2
        },
        "llm_analyzer": {
          "severity": "HIGH",
          "threat_names": ["SUSPICIOUS CODE EXECUTION"],
          "threat_summary": "Detected 1 threat: tool poisoning",
          "total_findings": 1
        }
      },
      "is_safe": false
    }
  ]
}
```

**Formatted Response (Summary, Table, etc.):**
```json
{
  "server_url": "https://mcp-server.example.com/mcp",
  "output_format": "summary",
  "formatted_output": "formatted text or structured data here",
  "raw_results": [...] // Original data for reference
}
```

## API Endpoints

### POST /scan-tool
Scan a specific tool on an MCP server.

### POST /scan-all-tools  
Scan all tools available on an MCP server.

## API Documentation

Once the server is running, you can access the interactive API documentation at:

- Swagger UI: `http://localhost:8001/docs`

## Testing Your Setup

1. **Start the API server:**
   ```bash
   mcp-scanner-api --port 8001
   ```

2. **Start your MCP server** (example on port 8000)

3. **Test with a basic scan:**
   ```bash
   curl -X POST "http://localhost:8001/scan-all-tools" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{
       "server_url": "https://mcp-server.example.com/mcp",
       "analyzers": ["yara"],
       "output_format": "summary",
       "severity_filter": "all",
       "analyzer_filter": null,
       "tool_filter": null,
       "hide_safe": false,
       "show_stats": true,
       "rules_path": null
     }'
   ```

4. **Try different formats:**
   - Change `"output_format"` to `"table"`, `"by_severity"`, `"detailed"`, etc.
   - Add `"severity_filter": "high"` to see only critical findings
   - Set `"hide_safe": true` to focus on vulnerable tools only
   - Use `"analyzers": ["api", "yara", "llm"]` to enable multiple analyzers

   ```bash
   curl -X POST "http://localhost:8001/scan-all-tools" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{
       "server_url": "https://mcp-server.example.com/mcp",
       "analyzers": ["yara"],
       "output_format": "summary",
       "severity_filter": "all",
       "analyzer_filter": null,
       "tool_filter": null,
       "hide_safe": false,
       "show_stats": true,
       "rules_path": null
     }'
   ```
