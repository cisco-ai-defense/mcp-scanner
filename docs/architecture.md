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
- **BehavioralCodeAnalyzer**: LLM-powered behavioral analysis with cross-file dataflow tracking, alignment checking, and comprehensive threat taxonomy mapping (AITech/AISubtech).

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

## Behavioral Code Analyzer: Advanced Architecture

The Behavioral Code Analyzer is the next-generation evolution of source code analysis in MCP Scanner. It combines LLM-powered behavioral analysis with cross-file dataflow tracking, alignment checking, and comprehensive threat taxonomy mapping to detect sophisticated threats in MCP tools.

### Key Innovations

1. **LLM-Powered Alignment Checking**: Uses LLM to compare docstring claims against actual code behavior
2. **Cross-File Dataflow Analysis**: Tracks parameter flows across multiple files and imported functions
3. **Cisco AI Threat Security Taxonomy Integration**: Maps every threat to Cisco AI Threat Security taxonomy (AITech/AISubtech)
4. **16 Threat Categories**: Comprehensive coverage of behavioral threats with detailed classifications
5. **Static Analysis Safety**: Analyzes code without execution - safe for scanning malicious code

### Component Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      CLI / Scanner Entry Point                      │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    BehavioralCodeAnalyzer                           │
│  • Finds Python files (.py)                                         │
│  • Parses AST and extracts MCP entry points                         │
│  • Orchestrates analysis workflow                                   │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
┌────────────────────────────────────┐  ┌──────────────────────────────┐
│   Python Parser / AST Extractor    │  │ CrossFileDataflowAnalyzer    │
│  • Detect @mcp.tool() decorators   │  │ • Trace parameter flows      │
│  • Extract function metadata       │  │ • Resolve imports            │
│  • Build function context          │  │ • Build call graphs          │
└────────────────────┬───────────────┘  └────────────┬─────────────────┘
                     │                               │
                     └───────────────┬───────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    AlignmentOrchestrator                            │
│  • Coordinates alignment checking workflow                          │
│  • Manages component interactions                                   │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │  AlignmentPromptBuilder       │
                    │  • Load prompt template       │
                    │  • Inject code context        │
                    │  • Include dataflow           │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │  AlignmentLLMClient           │
                    │  • Call OpenAI API            │
                    │  • Handle retries             │
                    │  • Error recovery             │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      LLM Analysis             │
                    │  • Compare docstring vs code  │
                    │  • Detect hidden behavior     │
                    │  • Classify threat type       │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │  AlignmentResponseValidator    │
                    │  • Validate structure          │
                    │  • Parse JSON response         │
                    │  • Normalize severity          │
                    └────────────────┬───────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         ThreatMapper                                │
│  • Map threat name → taxonomy                                       │
│  • Provide AITech/AISubtech codes                                   │
│  • Include descriptions and severity                                │
└───────────────────────────────────┬─────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      SecurityFinding Objects                        │
│  • Threat name, severity, confidence                                │
│  • AITech/AISubtech taxonomy                                        │
│  • Detailed descriptions and evidence                               │
│  • Line numbers and code snippets                                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Core Components

#### 1. BehavioralCodeAnalyzer (`behavioral/code_analyzer.py`)

**Main orchestrator** that coordinates the entire behavioral analysis workflow.

**Responsibilities:**
- Find and parse Python files in target directory
- Extract MCP entry points (`@mcp.tool()`, `@mcp.resource()`, `@mcp.prompt()`)
- Build comprehensive function context with metadata
- Integrate with alignment orchestrator for LLM analysis
- Aggregate and return security findings

**Key Methods:**
- `analyze(target_path, context)` - Main entry point for analysis
- `_find_python_files(path)` - Recursively find .py files
- `_parse_python_file(file_path)` - Parse AST and extract functions

**Usage:**
```python
from mcpscanner.core.analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer
from mcpscanner import Config

config = Config(llm_provider_api_key="your-openai-key", llm_model="gpt-4o-mini")
analyzer = BehavioralCodeAnalyzer(config)
findings = await analyzer.analyze("./mcp-server/", context={"file_path": "./mcp-server/"})
```

#### 2. AlignmentOrchestrator (`behavioral/alignment/alignment_orchestrator.py`)

**Coordinates the alignment checking workflow** - the core of behavioral threat detection.

**Responsibilities:**
- Build analysis prompts with code context and dataflow evidence
- Call LLM API to analyze docstring vs. implementation alignment
- Validate and parse LLM responses
- Map threat names to taxonomy using ThreatMapper
- Create SecurityFinding objects with complete metadata

**Key Methods:**
- `check_alignment(function_context)` - Main alignment check
- `_create_finding(analysis_result, function_context)` - Build SecurityFinding with taxonomy

**Process Flow:**
1. Receive function context from BehavioralCodeAnalyzer
2. Build comprehensive prompt via AlignmentPromptBuilder
3. Send to LLM via AlignmentLLMClient
4. Validate response via AlignmentResponseValidator
5. Map threat to taxonomy via ThreatMapper
6. Return enriched SecurityFinding

#### 3. AlignmentPromptBuilder (`behavioral/alignment/alignment_prompt_builder.py`)

**Builds comprehensive analysis prompts** for the LLM to evaluate alignment.

**Prompt Template:** `code_alignment_threat_analysis_prompt.md`

**Prompt Contents:**
- Threat definitions with examples (16 threat categories)
- Dataflow analysis instructions
- Severity classification guidelines
- Required JSON output format
- Security analysis principles