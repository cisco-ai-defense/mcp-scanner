# Architecture

The MCP Scanner is organized into the following components:

## Core Components

- **Config**: Manages API configuration including API key and endpoint URL.
- **Scanner**: Main class for scanning MCP servers, tools, prompts, and resources.
- **Result**: Contains result classes (`ScanResult`, `PromptScanResult`, `ResourceScanResult`) and utility methods for processing scan results.

## Analyzers

- **ApiAnalyzer**: Handles API-based scanning using Cisco AI Defense for malicious intent detection.
- **YaraAnalyzer**: Handles YARA pattern matching for detecting known malicious patterns and signatures.
- **LLMAnalyzer**: Advanced AI-powered analysis using configurable LLM models for sophisticated threat detection.

## Utility Methods

- **process_scan_results**: Processes a list of scan results and returns summary statistics.
- **filter_results_by_severity**: Filters scan results by severity level (high, medium, low).

## Data Models

- **SecurityFinding**: Represents a single security finding from an analyzer.
- **ScanResult**: Aggregates all findings from a tool scan.
- **PromptScanResult**: Aggregates all findings from a prompt scan.
- **ResourceScanResult**: Aggregates all findings from a resource scan.

## Configuration

### API Configuration

The `Config` class manages the API configuration:

```python
from mcpscanner import Config

# Default endpoint (US production)
config = Config(api_key="your_api_key")

# Custom endpoint
config = Config(api_key="your_api_key", endpoint_url="https://eu.api.inspect.aidefense.security.cisco.com/api/v1")
```
