# Static/Offline Analyzer for MCP Scanner

## Overview

The **Static Analyzer** enables scanning of pre-generated MCP JSON files without connecting to a live MCP server. This is perfect for CI/CD pipelines, offline environments, and reproducible security testing.

## Features

✅ **Offline Scanning** - No live MCP server required
✅ **Fast** - YARA scans complete in milliseconds
✅ **CI/CD Ready** - Easy integration with build pipelines
✅ **Deterministic** - Same input always produces same output
✅ **Air-gapped Support** - Works in restricted network environments
✅ **Version Control Friendly** - Store scan snapshots in git

## Files Created

### 1. Core Implementation
- **`mcpscanner/core/analyzers/static_analyzer.py`**
  Main StaticAnalyzer class that coordinates scanning of JSON files

### 2. Comprehensive Tests
- **`tests/test_static_analyzer.py`**
  19 test cases covering all functionality:
  - Basic operations (initialization, file loading)
  - Tools scanning (safe and malicious)
  - Prompts scanning
  - Resources scanning (with MIME type filtering)
  - Edge cases and error handling

### 3. Working Example
- **`examples/static_scanning_example.py`**
  Complete examples demonstrating:
  - YARA-only scanning
  - Multi-analyzer scanning (YARA + LLM)
  - Scanning tools, prompts, and resources
  - CI/CD integration patterns

## Usage

### Basic Example

```python
import asyncio
from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer
from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer

async def scan():
    # Initialize analyzers
    yara = YaraAnalyzer()
    static = StaticAnalyzer(analyzers=[yara])

    # Scan tools from JSON file
    results = await static.scan_tools_file("tools-list.json")

    # Check results
    for result in results:
        if not result["is_safe"]:
            print(f"⚠️ {result['tool_name']}: {len(result['findings'])} findings")

asyncio.run(scan())
```

### Expected JSON Format

#### Tools List (`tools/list` output)
```json
{
  "tools": [
    {
      "name": "tool_name",
      "description": "Tool description",
      "inputSchema": {
        "type": "object",
        "properties": {
          "param": {"type": "string"}
        }
      }
    }
  ]
}
```

#### Prompts List (`prompts/list` output)
```json
{
  "prompts": [
    {
      "name": "prompt_name",
      "description": "Prompt description",
      "arguments": [
        {
          "name": "arg_name",
          "required": true
        }
      ]
    }
  ]
}
```

#### Resources List (`resources/list` output)
```json
{
  "resources": [
    {
      "uri": "file:///path/to/resource",
      "name": "Resource name",
      "description": "Resource description",
      "mimeType": "text/plain"
    }
  ]
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install MCP Scanner
        run: pip install cisco-ai-mcp-scanner

      - name: Generate MCP Snapshots
        run: python scripts/generate_mcp_snapshots.py

      - name: Run Security Scan
        run: |
          python -c "
          import asyncio
          from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer
          from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer

          async def scan():
              yara = YaraAnalyzer()
              static = StaticAnalyzer(analyzers=[yara])
              results = await static.scan_tools_file('output/tools-list.json')
              unsafe = [r for r in results if not r['is_safe']]

              if unsafe:
                  print(f'❌ {len(unsafe)} unsafe tools detected')
                  exit(1)
              else:
                  print('✅ Security scan passed')
                  exit(0)

          asyncio.run(scan())
          "
```

## API Reference

### StaticAnalyzer Class

```python
class StaticAnalyzer:
    """Coordinator for scanning static MCP JSON files."""

    def __init__(
        self,
        analyzers: Optional[List[BaseAnalyzer]] = None,
        config: Optional[Any] = None
    ):
        """Initialize with list of sub-analyzers (YARA, LLM, API, etc.)"""

    async def scan_tools_file(self, file_path: Union[str, Path]) -> List[Dict]:
        """Scan tools from JSON file."""

    async def scan_prompts_file(self, file_path: Union[str, Path]) -> List[Dict]:
        """Scan prompts from JSON file."""

    async def scan_resources_file(
        self,
        file_path: Union[str, Path],
        allowed_mime_types: Optional[List[str]] = None
    ) -> List[Dict]:
        """Scan resources from JSON file with optional MIME type filtering."""
```

### Return Format

```python
{
    "tool_name": str,           # or "prompt_name", "resource_name"
    "tool_description": str,
    "is_safe": bool,            # True if no findings
    "findings": List[SecurityFinding],
    "status": str,              # "completed" or "skipped"
    "analyzers": List[str]      # Names of analyzers used
}
```

## Running Tests

```bash
# Set up virtual environment
cd /path/to/mcp-scanner
uv venv .venv
source .venv/bin/activate

# Install dependencies
uv pip install -e .
uv pip install pytest pytest-asyncio

# Run tests
pytest tests/test_static_analyzer.py -v
```

**Test Results**: ✅ All 19 tests passing

## Running Examples

```bash
# Activate venv
source .venv/bin/activate

# Run comprehensive examples
python examples/static_scanning_example.py
```

## Advantages Over Live Server Scanning

| Feature | Static Scanning | Live Server Scanning |
|---------|----------------|----------------------|
| **Network Required** | ❌ No | ✅ Yes |
| **Server Must Be Running** | ❌ No | ✅ Yes |
| **Credentials Needed** | ❌ No | ✅ Often |
| **Reproducible** | ✅ 100% | ⚠️ Server may change |
| **Speed** | ✅ Very Fast | ⚠️ Network latency |
| **CI/CD Friendly** | ✅ Perfect | ⚠️ Complex setup |
| **Air-gapped Support** | ✅ Yes | ❌ No |
| **Version Control** | ✅ Can commit snapshots | ❌ No |

## Use Cases

### 1. CI/CD Security Gates
- Scan MCP server code before deployment
- Block merges if security issues detected
- Track security posture over time

### 2. Offline/Air-gapped Environments
- Scan in restricted networks
- No external API calls required (with YARA)
- Security audits without internet

### 3. Regression Testing
- Store baseline scans in git
- Detect new security issues in PRs
- Reproducible security testing

### 4. Compliance & Auditing
- Generate security reports for compliance
- Historical scan data for audits
- Evidence of security due diligence

## Combining with Other Analyzers

```python
from mcpscanner import Config
from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer
from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
from mcpscanner.core.analyzers.api_analyzer import ApiAnalyzer

# Use all three analyzers for comprehensive scanning
config = Config(
    api_key="cisco_api_key",
    llm_provider_api_key="openai_key"
)

yara = YaraAnalyzer()
llm = LLMAnalyzer(config)
api = ApiAnalyzer(config)

# Static analyzer coordinates all three
static = StaticAnalyzer(analyzers=[yara, llm, api])

results = await static.scan_tools_file("tools.json")
```

## Limitations

- ❌ Cannot scan actual tool execution behavior
- ❌ Only analyzes metadata, not runtime behavior
- ❌ Requires manual generation of JSON snapshots
- ❌ May miss context-dependent vulnerabilities

## Next Steps

To fully integrate this feature:

1. ✅ **Code written** - StaticAnalyzer class complete
2. ✅ **Tests passing** - 19/19 tests green
3. ✅ **Examples working** - Full demo script functional
4. ⏳ **Export to `__init__.py`** - Make publicly available
5. ⏳ **CLI integration** - Add `--static` flags to CLI
6. ⏳ **Documentation** - Add to main docs
7. ⏳ **GitHub issue** - Create feature request (as discussed earlier)

## Related Issue

This implementation addresses the use case described in the GitHub issue you wanted to create:
- **Static/Offline scanning mode**
- **CI/CD pipeline integration**
- **No live server or credentials required**
- **Reproducible security scanning**

## Support

For questions or issues with the Static Analyzer:
1. Check the examples: `examples/static_scanning_example.py`
2. Review tests: `tests/test_static_analyzer.py`
3. Open an issue on GitHub
4. Refer to main MCP Scanner documentation

---

**Status**: ✅ Fully implemented and tested
**Version**: Compatible with mcp-scanner v3.1.1+
**License**: Apache 2.0
