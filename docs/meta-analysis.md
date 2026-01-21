# Meta-Analysis

The Meta-Analyzer is an optional second-pass LLM analysis feature that reviews findings from other analyzers to improve accuracy and provide actionable insights.

## Overview

When enabled via the `--enable-meta` CLI flag or `enable_meta` API parameter, the Meta-Analyzer performs:

- **False Positive Filtering**: Identifies and removes false positives based on context
- **Priority Ranking**: Ranks findings by actual exploitability and impact
- **Correlation**: Groups related findings across different analyzers
- **Recommendations**: Provides specific remediation guidance

## CLI Usage

```bash
# Enable meta-analysis with remote server
mcp-scanner --analyzers yara,llm --enable-meta --format summary \
  remote --server-url https://mcp.example.com/mcp

# Meta-analysis with stdio server
mcp-scanner --analyzers yara,llm --enable-meta --format summary \
  stdio --stdio-command uvx \
  --stdio-arg=--from --stdio-arg=mcp-server-fetch --stdio-arg=mcp-server-fetch

# Meta-analysis with known configs
mcp-scanner --analyzers yara,llm --enable-meta --format detailed known-configs

# Meta-analysis with prompts scanning
mcp-scanner --analyzers llm --enable-meta prompts --server-url http://127.0.0.1:8000/mcp

# Meta-analysis with resources scanning
mcp-scanner --analyzers llm --enable-meta resources --server-url http://127.0.0.1:8000/mcp

# Meta-analysis with instructions scanning
mcp-scanner --analyzers llm --enable-meta instructions --server-url http://127.0.0.1:8000/mcp
```

## API Usage

All scan endpoints support the `enable_meta` parameter:

```bash
curl -X POST "http://localhost:8001/scan-all-tools" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "server_url": "https://mcp.example.com/mcp",
    "analyzers": ["yara", "llm"],
    "enable_meta": true
  }'
```

### Supported Endpoints

- `/scan-tool` - Single tool scan with meta-analysis
- `/scan-all-tools` - All tools scan with meta-analysis
- `/scan-prompt` - Single prompt scan with meta-analysis
- `/scan-all-prompts` - All prompts scan with meta-analysis
- `/scan-resource` - Single resource scan with meta-analysis
- `/scan-all-resources` - All resources scan with meta-analysis
- `/scan-instructions` - Server instructions scan with meta-analysis

## Configuration

The meta-analyzer uses the same LLM configuration as the LLM analyzer by default. You can optionally configure separate settings:

```bash
# Primary LLM settings (used if meta-specific not set)
export MCP_SCANNER_LLM_API_KEY="your_llm_api_key"
export MCP_SCANNER_LLM_MODEL="gpt-4o"
export MCP_SCANNER_LLM_BASE_URL="https://api.openai.com/v1"

# Optional: Meta-analyzer specific settings
export MCP_SCANNER_META_LLM_API_KEY="your_meta_llm_key"
export MCP_SCANNER_META_LLM_MODEL="azure/gpt-4"
export MCP_SCANNER_META_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export MCP_SCANNER_META_LLM_API_VERSION="2024-02-01"
```

### Azure OpenAI Example

```bash
export MCP_SCANNER_LLM_API_KEY="your-azure-api-key"
export MCP_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export MCP_SCANNER_LLM_API_VERSION="2024-02-15-preview"
export MCP_SCANNER_LLM_MODEL="azure/gpt-4.1"
```

### AWS Bedrock Example

```bash
export AWS_PROFILE="your-profile"
export AWS_REGION="us-east-1"
export MCP_SCANNER_LLM_MODEL="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0"
```

## How It Works

1. **Collect Findings**: The scanner runs all selected analyzers (YARA, LLM, API) and collects their findings
2. **Aggregate**: All findings are aggregated with their source analyzer information
3. **Meta-Analysis**: The LLM Meta-Analyzer reviews all findings together with:
   - Tool/prompt/resource context
   - Cross-analyzer correlation
   - False positive detection heuristics
4. **Filter & Enrich**: False positives are filtered out, and remaining findings are enriched with:
   - Confidence scores
   - Exploitability assessment
   - Impact analysis
   - Specific remediation recommendations

## Output

When meta-analysis is enabled, findings include additional metadata:

```json
{
  "severity": "HIGH",
  "summary": "Command injection vulnerability in execute_command tool",
  "threat_category": "INJECTION_ATTACKS",
  "analyzer": "META",
  "details": {
    "meta_validated": true,
    "meta_confidence": "HIGH",
    "meta_confidence_reason": "Multiple analyzers flagged this with consistent findings",
    "meta_exploitability": "Easy - no authentication required",
    "meta_impact": "Critical - allows arbitrary command execution"
  }
}
```

## Scan Types Supported

| Scan Type | Meta-Analysis Support |
|-----------|----------------------|
| remote | ✅ |
| stdio | ✅ |
| config | ✅ |
| known-configs | ✅ |
| prompts | ✅ |
| resources | ✅ |
| instructions | ✅ |
| static | ✅ |
| behavioral | ✅ |

## Best Practices

1. **Use with multiple analyzers**: Meta-analysis is most effective when correlating findings from multiple analyzers
2. **Review filtered findings**: Check the logs for false positives that were filtered
3. **Configure appropriate LLM**: Use a capable model (GPT-4, Claude 3.5+) for best results
4. **Consider latency**: Meta-analysis adds an additional LLM call, increasing scan time

## Troubleshooting

**Meta-analyzer not running:**
- Ensure `--enable-meta` flag is provided (CLI) or `enable_meta: true` in request (API)
- Check that LLM API key is configured
- Verify the scanner has the meta-analyzer initialized (check logs for "LLM Meta-Analyzer initialized")

**No findings after meta-analysis:**
- All findings may have been filtered as false positives
- Check logs for "Meta-analysis complete: X validated, Y false positives filtered out"

**Slow scans with meta-analysis:**
- Meta-analysis adds one additional LLM call per scan
- Consider using a faster model for meta-analysis via `MCP_SCANNER_META_LLM_MODEL`
