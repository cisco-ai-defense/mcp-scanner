# MCP Scanner Evaluation Suite

This directory contains evaluation datasets and scripts for testing the MCP Scanner's detection capabilities.

## Structure

```
evals/
└── behavioral-analysis/
    ├── data/           # Malicious MCP server test cases (141 files)
    │   ├── arbitrary-resource-read-write/
    │   ├── backdoor/
    │   ├── data-exfiltration/
    │   ├── defense-evasion/
    │   ├── general-description-code-mismatch/
    │   ├── goal-manipulation/
    │   ├── injection-attacks/
    │   ├── prompt-injection/
    │   ├── resource-exhaustion/
    │   ├── template-injection/
    │   ├── tool-poisoning/
    │   ├── unauthorized-code-execution/
    │   ├── unauthorized-network-access/
    │   └── unauthorized-system-access/
    └── scripts/
        ├── run_behavioral_scan.py
        └── scan_results.json (generated)
```

## Behavioral Analysis Evaluation

The behavioral analysis evaluation tests the scanner's ability to detect malicious patterns in MCP server source code through static analysis and LLM-powered alignment checking.

Eval corpus files use **`MCPServer`** (`from mcp.server.mcpserver import MCPServer`) to match mcp 2.0. The scanner's static analyzer still detects legacy **`FastMCP`** patterns when scanning older third-party code.

### Prerequisites

The behavioral analyzer requires LLM access. Set up your environment:

```bash
# For Azure OpenAI
export MCP_SCANNER_LLM_API_KEY="your_api_key"
export MCP_SCANNER_LLM_MODEL="azure/gpt-5.2"
export MCP_SCANNER_LLM_BASE_URL="https://your-endpoint.openai.azure.com/"
export MCP_SCANNER_LLM_API_VERSION="2025-04-01-preview"

# For OpenAI
export MCP_SCANNER_LLM_API_KEY="your_openai_key"
export MCP_SCANNER_LLM_MODEL="gpt-4o"

# For AWS Bedrock
export AWS_PROFILE="your-profile"
export AWS_REGION="us-east-1"
export MCP_SCANNER_LLM_MODEL="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0"
```

### Running the Evaluation

Navigate to the scripts directory and run:

```bash
cd evals/behavioral-analysis/scripts
uv run python run_behavioral_scan.py
```

### Example Output

```
================================================================================
Behavioral Analysis Evaluation Scanner
================================================================================

📂 Data directory: /path/to/evals/behavioral-analysis/data
🤖 LLM Model: azure/gpt-4.1
📊 Found 14 threat categories

📁 Scanning arbitrary-resource-read-write: 10 files
  🔍 arbitrary_file_copy_sensitive_data.py... ✅ DETECTED (3 findings)
  🔍 arbitrary_file_deletion_recursive.py... ✅ DETECTED (2 findings)
  🔍 path_traversal_directory_enumeration.py... ✅ DETECTED (4 findings)
  ...

📁 Scanning backdoor: 10 files
  🔍 dns_tunneling_c2_communication.py... ✅ DETECTED (5 findings)
  🔍 multi_layer_obfuscated_backdoor.py... ✅ DETECTED (3 findings)
  ...

================================================================================
SUMMARY
================================================================================
Total files scanned: 141
✅ Detected (with findings): 135
⚠️  Missed (no findings): 5
❌ Errors: 1

🎯 Detection Rate: 95.7%

💾 Detailed results saved to: scan_results.json
================================================================================
```

### Understanding Results

**Status Indicators:**
- ✅ **DETECTED** - Behavioral analyzer found security findings
- ⚠️ **MISSED** - No findings detected (potential false negative)
- ❌ **ERROR** - Analysis failed (check error details in JSON)

**Output Files:**
- `scan_results.json` - Detailed results with all findings per file

### Results Format

The `scan_results.json` file contains:

```json
{
  "summary": {
    "total_files": 141,
    "detected": 135,
    "missed": 5,
    "errors": 1,
    "detection_rate": "95.7%"
  },
  "results_by_category": {
    "arbitrary-resource-read-write": [
      {
        "file": "data/arbitrary-resource-read-write/arbitrary_file_copy_sensitive_data.py",
        "status": "completed",
        "is_safe": false,
        "findings_count": 3,
        "findings": [
          {
            "severity": "high",
            "summary": "Arbitrary file read/write without validation",
            "threat_category": "arbitrary-resource-read-write"
          }
        ]
      }
    ]
  }
}
```

## Threat Categories

### Data Directory

The `data/` directory contains 141 malicious MCP server implementations organized by threat type:

| Category | Description | Files |
|----------|-------------|-------|
| **arbitrary-resource-read-write** | File system manipulation attacks | 10 |
| **backdoor** | Backdoor and persistence mechanisms | 10 |
| **data-exfiltration** | Data theft and credential harvesting | 11 |
| **defense-evasion** | Anti-analysis and evasion techniques | 10 |
| **general-description-code-mismatch** | Misleading documentation | 10 |
| **goal-manipulation** | Goal hijacking and manipulation | 10 |
| **injection-attacks** | Various injection vulnerabilities | 10 |
| **prompt-injection** | Prompt injection patterns | 10 |
| **resource-exhaustion** | DoS and resource exhaustion | 10 |
| **template-injection** | Template injection vulnerabilities | 10 |
| **tool-poisoning** | Tool manipulation and poisoning | 10 |
| **unauthorized-code-execution** | Arbitrary code execution | 10 |
| **unauthorized-network-access** | SSRF and network attacks | 10 |
| **unauthorized-system-access** | System information disclosure | 10 |

## Adding New Test Cases

To add new malicious server implementations:

1. Choose the appropriate threat category in `data/`
2. Create a new Python file with a descriptive name
3. Implement the malicious MCP server pattern
4. Add Apache 2.0 license header
5. Run the evaluation script to verify detection

Example:

```bash
# Create new test case
cat > evals/behavioral-analysis/data/backdoor/my_new_backdoor.py << 'EOF'
# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""MCP server with hidden backdoor functionality."""

from mcp.server.mcpserver import MCPServer

app = MCPServer("my-eval-server")

# Your malicious implementation here
EOF

# Run evaluation
cd evals/behavioral-analysis/scripts
uv run python run_behavioral_scan.py
```

## Troubleshooting

### LLM Configuration Errors

If you see:
```
❌ Error: LLM configuration required for behavioral analysis
```

Ensure you've set the required environment variables (see Prerequisites above).

### Analysis Timeouts

For large files or complex analysis, you may need to increase the timeout:

```bash
export MCP_SCANNER_LLM_TIMEOUT=300  # 5 minutes
```

### Rate Limiting

If you encounter rate limits, consider:
- Using a higher-tier API plan
- Adding delays between requests
- Running on a subset of files first

## Performance Notes

- **Average time per file**: 10-30 seconds (depends on LLM provider)
- **Total runtime for 141 files**: ~30-60 minutes
- **Recommended**: Run during off-peak hours or use batch processing

## Contributing

When adding new evaluation test cases:

1. Ensure the malicious pattern is realistic and represents real threats
2. Add clear comments explaining the malicious behavior
3. Include proper license headers
4. Test that the behavioral analyzer detects the pattern
5. Document any special setup or dependencies

## License

All evaluation test cases are licensed under Apache 2.0.
