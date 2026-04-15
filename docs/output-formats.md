# Output Formats

The MCP Scanner supports multiple output formats to suit different use cases and preferences.

## Available Formats

- **`raw`**: Raw JSON output with complete scan results including hierarchical threat taxonomy
- **`summary`**: Concise summary showing only key findings
- **`detailed`**: Comprehensive output with full finding details and threat taxonomy information
- **`by_tool`**: Results grouped by scanned tool
- **`by_analyzer`**: Results grouped by analyzer type (API, YARA, LLM, VirusTotal)
- **`by_severity`**: Results grouped by severity level (HIGH, MEDIUM, LOW, UNKNOWN)
- **`table`**: Tabular format for easy reading

## JSON Output Flags: `--format raw` vs `--raw`

There are two ways to get JSON output, and they produce different structures:

| Flag | Envelope | Use case |
|------|----------|----------|
| `--format raw` | Wrapped in `{ "server_url", "scan_results", "requested_analyzers" }` | CI/CD pipelines, structured processing |
| `--raw` / `-r` | Bare array of scan result objects (no envelope) | Quick inspection, piping to `jq` |

```bash
# Envelope JSON (recommended for CI/CD)
mcp-scanner --format raw remote --server-url https://example.com/mcp

# Bare JSON array
mcp-scanner --raw remote --server-url https://example.com/mcp
```

---

## JSON Output Schema Reference

This section documents the complete JSON structure produced by `--format raw`, field by field. This is the recommended format for CI/CD pipelines and programmatic integrations.

### Top-Level Envelope

```json
{
  "server_url": "string",
  "scan_results": [ ... ],
  "requested_analyzers": [ ... ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `server_url` | `string` | Label identifying the scan target. Varies by mode (see [Mode-Specific Variations](#mode-specific-variations)). |
| `scan_results` | `array` | List of per-item result objects (tools, prompts, resources). |
| `requested_analyzers` | `array<string>` | Analyzers that were requested for this scan. Values: `"api"`, `"yara"`, `"llm"`, `"behavioral"`, `"virustotal"`, `"readiness"`. |

### Scan Result Object

Each element in `scan_results` has these common fields plus type-specific fields:

```json
{
  "status": "completed",
  "is_safe": false,
  "item_type": "tool",
  "findings": { ... },
  "tool_name": "execute_command",
  "tool_description": "Execute shell commands",
  "server_name": "my-server",
  "server_source": "/path/to/config.json"
}
```

#### Common Fields (always present)

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | Scan status. Typically `"completed"`. |
| `is_safe` | `boolean` | `true` if no threats were detected, `false` otherwise. |
| `findings` | `object` | Per-analyzer findings (see [Analyzer Findings Object](#analyzer-findings-object)). Empty `{}` when safe. |

#### Type-Specific Fields

The `item_type` field indicates the scanned item type, and determines which additional fields are present:

| `item_type` | Additional Fields | Description |
|-------------|-------------------|-------------|
| `"tool"` | `tool_name`, `tool_description` | MCP tool definition |
| `"prompt"` | `prompt_name`, `prompt_description` | MCP prompt template |
| `"resource"` | `resource_uri`, `resource_name`, `resource_mime_type` | MCP resource |

#### Optional Fields (present when applicable)

| Field | Type | When Present | Description |
|-------|------|--------------|-------------|
| `server_name` | `string` | Config-based scans | Name of the server from the MCP config file |
| `server_source` | `string` | Config-based scans | Path to the config file that defined this server |

### Analyzer Findings Object

The `findings` object is keyed by analyzer name in the format `{analyzer}_analyzer`:

```json
{
  "findings": {
    "yara_analyzer": { ... },
    "llm_analyzer": { ... },
    "api_analyzer": { ... }
  }
}
```

Possible keys: `api_analyzer`, `yara_analyzer`, `llm_analyzer`, `virustotal_analyzer`, `behavioral_analyzer`, `readiness_analyzer`, `prompt_defense_analyzer`.

Each analyzer entry has this structure:

```json
{
  "severity": "HIGH",
  "threat_names": ["CODE EXECUTION", "PROMPT INJECTION"],
  "threat_summary": "Detected 2 threats: code execution, prompt injection",
  "total_findings": 2,
  "mcp_taxonomies": [ ... ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `severity` | `string` | Rolled-up severity: `"HIGH"`, `"MEDIUM"`, `"LOW"`, or `"SAFE"`. Highest severity across all findings for this analyzer wins. |
| `threat_names` | `array<string>` | List of distinct threat types detected (e.g., `"PROMPT INJECTION"`, `"CODE EXECUTION"`, `"DATA EXFILTRATION"`). |
| `threat_summary` | `string` | Human-readable summary. Either the analyzer's own summary or auto-generated from `threat_names`. `"No threats detected"` when safe. |
| `total_findings` | `integer` | Number of individual findings from this analyzer. `0` when safe. |
| `mcp_taxonomies` | `array<object>` | List of unique MCP taxonomy entries (see below). Only present when findings have taxonomy mappings. |

#### Severity Rollup Logic

The `severity` field is the **maximum** severity across all findings for that analyzer:

```
HIGH > MEDIUM > LOW > SAFE
```

An analyzer with no findings has `severity: "SAFE"`.

### MCP Taxonomy Object

Each entry in `mcp_taxonomies` maps a detected threat to the standardized MCP threat taxonomy:

```json
{
  "scanner_category": "CODE EXECUTION",
  "aitech": "AITech-9.1",
  "aitech_name": "Model or Agentic System Manipulation",
  "aisubtech": "AISubtech-9.1.1",
  "aisubtech_name": "Code Execution",
  "description": "Autonomously generating, interpreting, or executing code..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `scanner_category` | `string` | The scanner's threat category name (matches values in `threat_names`). |
| `aitech` | `string` | AITech technique ID (e.g., `AITech-1.1`, `AITech-9.1`, `AITech-12.1`). |
| `aitech_name` | `string` | Human-readable technique name. |
| `aisubtech` | `string` | AISubtech sub-technique ID (e.g., `AISubtech-1.1.1`). |
| `aisubtech_name` | `string` | Human-readable sub-technique name. |
| `description` | `string` | Detailed description of the threat. |

Taxonomies are **deduplicated** per analyzer — each unique `(aitech, aisubtech)` pair appears at most once.

For the full taxonomy reference, see [MCP Threats Taxonomy](mcp-threats-taxonomy.md).

### Complete Example

```json
{
  "server_url": "https://mcp-server.example.com/mcp",
  "scan_results": [
    {
      "status": "completed",
      "is_safe": false,
      "tool_name": "execute_command",
      "tool_description": "Execute arbitrary shell commands on the host system",
      "item_type": "tool",
      "findings": {
        "yara_analyzer": {
          "severity": "HIGH",
          "threat_names": ["CODE EXECUTION"],
          "threat_summary": "Detected 1 threat: code execution",
          "total_findings": 1,
          "mcp_taxonomies": [
            {
              "scanner_category": "CODE EXECUTION",
              "aitech": "AITech-9.1",
              "aitech_name": "Model or Agentic System Manipulation",
              "aisubtech": "AISubtech-9.1.1",
              "aisubtech_name": "Code Execution",
              "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution."
            }
          ]
        },
        "llm_analyzer": {
          "severity": "HIGH",
          "threat_names": ["PROMPT INJECTION", "DATA EXFILTRATION"],
          "threat_summary": "Detected 2 threats: prompt injection, data exfiltration",
          "total_findings": 2,
          "mcp_taxonomies": [
            {
              "scanner_category": "PROMPT INJECTION",
              "aitech": "AITech-1.1",
              "aitech_name": "Direct Prompt Injection",
              "aisubtech": "AISubtech-1.1.1",
              "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
              "description": "Explicit attempts to override, replace, or modify the model's system instructions."
            },
            {
              "scanner_category": "DATA EXFILTRATION",
              "aitech": "AITech-8.2",
              "aitech_name": "Data Exfiltration / Exposure",
              "aisubtech": "AISubtech-8.2.3",
              "aisubtech_name": "Data Exfiltration via Agent Tooling",
              "description": "Unauthorized exposure or exfiltration of sensitive information through agent tools."
            }
          ]
        }
      }
    },
    {
      "status": "completed",
      "is_safe": true,
      "tool_name": "calculator",
      "tool_description": "Perform basic arithmetic",
      "item_type": "tool",
      "findings": {
        "yara_analyzer": {
          "severity": "SAFE",
          "threat_names": [],
          "threat_summary": "No threats detected",
          "total_findings": 0
        },
        "llm_analyzer": {
          "severity": "SAFE",
          "threat_names": [],
          "threat_summary": "No threats detected",
          "total_findings": 0
        }
      }
    },
    {
      "status": "completed",
      "is_safe": false,
      "prompt_name": "system_override",
      "prompt_description": "A prompt template that attempts system manipulation",
      "item_type": "prompt",
      "findings": {
        "llm_analyzer": {
          "severity": "MEDIUM",
          "threat_names": ["PROMPT INJECTION"],
          "threat_summary": "Prompt injection attempt detected",
          "total_findings": 1,
          "mcp_taxonomies": [
            {
              "scanner_category": "PROMPT INJECTION",
              "aitech": "AITech-1.1",
              "aitech_name": "Direct Prompt Injection",
              "aisubtech": "AISubtech-1.1.1",
              "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
              "description": "Explicit attempts to override, replace, or modify the model's system instructions."
            }
          ]
        }
      }
    },
    {
      "status": "completed",
      "is_safe": true,
      "resource_uri": "file://data/report.csv",
      "resource_name": "report.csv",
      "resource_mime_type": "text/csv",
      "item_type": "resource",
      "findings": {}
    }
  ],
  "requested_analyzers": ["yara", "llm"]
}
```

---

## Mode-Specific Variations

The `server_url` field and output structure vary by scan mode:

| Mode | `server_url` value | Additional fields on results |
|------|-------------------|------------------------------|
| `remote` | The server URL (e.g., `https://mcp.example.com/mcp`) | — |
| `stdio` | `stdio:<command> <args>` (e.g., `stdio:uvx mcp-server-fetch`) | — |
| `config` | The config file path (e.g., `/path/to/mcp_config.json`) | `server_name`, `server_source` |
| `known-configs` | `well-known-configs` | `server_name`, `server_source` |
| `static` | — (uses `--format raw` envelope) | — |

### `known-configs` with `--raw`

When using `--raw` with `known-configs`, the output is a map of config paths to result arrays instead of the standard envelope:

```json
{
  "/Users/me/.cursor/mcp.json": [
    { "status": "completed", "is_safe": true, ... }
  ],
  "/Users/me/.config/claude/claude_desktop_config.json": [
    { "status": "completed", "is_safe": false, ... }
  ]
}
```

---

## CI/CD Integration Examples

### Count unsafe tools

```bash
UNSAFE=$(mcp-scanner --format raw --analyzers yara \
  stdio --stdio-command uvx --stdio-arg mcp-server-fetch \
  | jq '[.scan_results[] | select(.is_safe == false)] | length')

if [ "$UNSAFE" -gt 0 ]; then
  echo "Found $UNSAFE unsafe tools"
  exit 1
fi
```

### Extract high-severity findings

```bash
mcp-scanner --format raw --analyzers yara,llm \
  remote --server-url https://mcp.example.com/mcp \
  | jq '.scan_results[] | select(.is_safe == false) | {
    name: .tool_name,
    findings: [.findings | to_entries[] | select(.value.severity == "HIGH") | {
      analyzer: .key,
      threats: .value.threat_names,
      summary: .value.threat_summary
    }]
  }'
```

### Check against an allowlist

```bash
RESULTS=$(mcp-scanner --format raw --analyzers yara \
  stdio --stdio-command uvx --stdio-arg my-mcp-server)

echo "$RESULTS" | jq -r '.scan_results[] | select(.is_safe == false) | .tool_name' | while read tool; do
  if ! grep -q "^$tool$" allowlist.txt; then
    echo "BLOCKED: $tool is not in the allowlist"
    exit 1
  fi
done
```

### Generate a summary report

```bash
mcp-scanner --format raw --analyzers yara,llm \
  remote --server-url https://mcp.example.com/mcp \
  | jq '{
    target: .server_url,
    analyzers: .requested_analyzers,
    total_items: (.scan_results | length),
    safe: [.scan_results[] | select(.is_safe)] | length,
    unsafe: [.scan_results[] | select(.is_safe == false)] | length,
    high_severity: [.scan_results[].findings | to_entries[] | select(.value.severity == "HIGH")] | length,
    all_threats: [.scan_results[].findings | to_entries[] | .value.threat_names[]?] | unique
  }'
```

---

## Statistics (`--stats`)

The `--stats` flag prints scan statistics to the terminal alongside the formatted output. Statistics are displayed as human-readable text and are **not** included in the JSON output.

```bash
mcp-scanner --stats remote --server-url https://mcp.example.com/mcp
```

```
Scan Statistics:
  Total items scanned: 5
  Safe: 3
  Unsafe: 2
  Severity breakdown:
    HIGH: 2
    MEDIUM: 1
    LOW: 0
    UNKNOWN: 0
    SAFE: 3
  Analyzer breakdown:
    yara_analyzer: 5 scanned, 2 with findings
    llm_analyzer: 5 scanned, 1 with findings
```

---

## Format Examples

### Summary Format
```bash
mcp-scanner --format summary remote --server-url http://127.0.0.1:8001/sse
```
Shows a concise overview with tool names, overall status, and highest severity findings.

### Detailed Format
```bash
mcp-scanner --format detailed remote --server-url http://127.0.0.1:8001/sse
```
Provides comprehensive output with full finding details, including hierarchical MCP taxonomy information for all analyzers.

### By Severity Format
```bash
mcp-scanner --format by_severity remote --server-url http://127.0.0.1:8001/sse
```
Groups all findings by severity level, making it easy to prioritize security issues.

### Table Format
```bash
mcp-scanner --format table remote --server-url http://127.0.0.1:8001/sse
```
Displays results in a clean tabular format with columns for tool, analyzer, severity, and findings.

## Filtering Options

### Severity Filtering
```bash
# Show only high severity findings
mcp-scanner --severity-filter high remote --server-url http://127.0.0.1:8001/sse

# Available severity levels: high, medium, low, unknown
```

### Analyzer Filtering
```bash
# Show only YARA analyzer results
mcp-scanner --analyzer-filter yara_analyzer remote --server-url http://127.0.0.1:8001/sse

# Available analyzers: api_analyzer, yara_analyzer, llm_analyzer, virustotal_analyzer, vulnerable_package_analyzer
```

### Additional Options
```bash
# Hide tools with no security findings
mcp-scanner --hide-safe remote --server-url http://127.0.0.1:8001/sse

# Show scan statistics
mcp-scanner --stats remote --server-url http://127.0.0.1:8001/sse

# Combine multiple options
mcp-scanner --format by_severity --severity-filter high,medium --stats remote --server-url http://127.0.0.1:8001/sse
```

## Example Output

### Raw Format
```json
{
  "server_url": "http://127.0.0.1:8001/sse",
  "scan_results": [
    {
      "item_type": "tool",
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
    },
    {
      "item_type": "prompt",
      "prompt_name": "malicious_prompt",
      "prompt_description": "A prompt template",
      "status": "completed",
      "is_safe": false,
      "findings": {
        "llm_analyzer": {
          "severity": "HIGH",
          "total_findings": 1
        }
      }
    },
    {
      "item_type": "resource",
      "resource_uri": "file://test/data.html",
      "resource_name": "data.html",
      "resource_mime_type": "text/html",
      "status": "completed",
      "is_safe": true,
      "findings": {}
    }
  ]
}
```

**Note:** The `item_type` field indicates whether the result is for a `tool`, `prompt`, or `resource`. Each type has specific fields:
- **Tools**: `tool_name`, `tool_description`
- **Prompts**: `prompt_name`, `prompt_description`
- **Resources**: `resource_uri`, `resource_name`, `resource_mime_type`
- **Vulnerable Packages**: `package_name`, `vulnerability_description` (uses `mcp_server_repository` instead of `server_url` at the top level)

## Human-Readable Output Examples

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

Prompt 2: suspicious_prompt
Status: completed
Safe: No
Analyzer Results:
  • llm_analyzer:
    - Severity: MEDIUM
    - Threat Summary: Prompt injection attempt detected
    - Total Findings: 1

Resource 3: data.html
URI: file://test/data.html
MIME Type: text/html
Status: completed
Safe: Yes
```

### Summary Format
```
=== MCP Scanner Results Summary ===

Scan Target: http://127.0.0.1:8001/sse
Total tools scanned: 5
Items matching filters: 5
Safe items: 3
Unsafe items: 2

=== Unsafe Items ===
1. execute_command (tool) - HIGH (1 findings)
2. malicious_prompt (prompt) - MEDIUM (1 findings)
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
