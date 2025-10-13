# Architecture

The MCP Scanner is organized into the following components:

## Core Components

- **Config**: Manages API configuration including API key and endpoint URL.
- **Scanner**: Main class for scanning MCP servers, tools, prompts, and resources.
- **Result**: Contains result classes (`ScanResult`, `ToolScanResult`, `PromptScanResult`, `ResourceScanResult`) and utility methods for processing scan results.

## Analyzers

- **ApiAnalyzer**: Handles API-based scanning using Cisco AI Defense for malicious intent detection.
- **YaraAnalyzer**: Handles YARA pattern matching for detecting known malicious patterns and signatures.
- **LLMAnalyzer**: Advanced AI-powered analysis using configurable LLM models for sophisticated threat detection.

## Utility Methods

All utility methods support Union types (v2.0.0+), accepting `ToolScanResult`, `PromptScanResult`, or `ResourceScanResult`:

- **process_scan_results**: Processes a list of scan results and returns summary statistics.
- **filter_results_by_severity**: Filters scan results by severity level (high, medium, low). Preserves the original result type.
- **format_results_as_json**: Formats scan results as JSON, dynamically handling all three result types.
- **format_results_by_analyzer**: Formats results grouped by analyzer, with appropriate naming based on result type.

## Data Models

The scanner uses an inheritance hierarchy for scan results:

- **SecurityFinding**: Represents a single security finding from an analyzer.
- **ScanResult**: Base class that aggregates common scan information (status, analyzers, findings, server info).
- **ToolScanResult**: Extends `ScanResult` for tool scans, adding `tool_name` and `tool_description`.
- **PromptScanResult**: Extends `ScanResult` for prompt scans, adding `prompt_name` and `prompt_description`.
- **ResourceScanResult**: Extends `ScanResult` for resource scans, adding `resource_uri`, `resource_name`, and `resource_mime_type`.

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
