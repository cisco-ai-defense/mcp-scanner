# mcpscanner/AGENTS.md

This file provides detailed context for AI coding agents working on the **core scanner implementation** in the `mcpscanner/` directory.

**📁 Parent Guide:** [`../AGENTS.md`](../AGENTS.md) - Global project overview and rules

---

## Directory Overview

The `mcpscanner/` directory contains the core scanner implementation with the following structure:

```
mcpscanner/
├── core/               # Scanner engine and analysis components
│   ├── analyzers/      # Security analyzers
│   │   ├── behavioral/ # Behavioral analysis (description-code mismatch)
│   │   ├── api.py      # Cisco AI Defense API analyzer
│   │   ├── llm.py      # LLM-powered threat detection
│   │   └── yara.py     # YARA pattern matching
│   ├── static_analysis/ # Static code analysis utilities
│   ├── scanner.py      # Main scanner orchestration
│   ├── result.py       # Result data structures
│   ├── models.py       # Data models for findings
│   ├── auth.py         # Authentication handling
│   └── report_generator.py # Output formatting
├── api/                # API client implementations
├── config/             # Configuration management
├── data/               # Static data files
│   ├── prompts/        # LLM prompts for analysis
│   ├── yara_rules/     # YARA detection rules
│   └── taxonomies/     # Threat classification taxonomies
├── threats/            # Threat definitions
├── utils/              # Utility functions
├── cli.py              # Command-line interface (1500+ lines)
└── server.py           # MCP server implementation
```

## Core Components

### `/core/scanner.py` - Main Orchestrator (96KB)

**Purpose**: Coordinates all analyzers, handles MCP communication, and manages scan lifecycle.

**Key Methods**:
- `scan_remote_server()`: Scan remote MCP server via HTTP/SSE
- `scan_stdio_server()`: Scan MCP server via stdio (local command)
- `scan_local_code()`: Scan local source code for behavioral issues
- `scan_prompts()`: Scan MCP prompts on a server
- `scan_resources()`: Scan MCP resources on a server
- `scan_instructions()`: Scan server instructions

**Usage**:
```python
scanner = Scanner(config, rules_dir=rules_path)
results = await scanner.scan_remote_server(server_url, analyzers=[...])
```

### `/core/result.py` - Result Data Structures (22KB)

**Key Classes**:
- `ToolScanResult`: Results for individual MCP tools
- `PromptScanResult`: Results for MCP prompts
- `ResourceScanResult`: Results for MCP resources
- `InstructionsScanResult`: Results for server instructions
- `SecurityFinding`: Core data structure for all findings

### `/core/models.py` - Data Models (11KB)

Core data models for findings, threats, and analysis results.

### `/core/auth.py` - Authentication (17KB)

Handles authentication for MCP servers:
- Bearer tokens
- API keys
- OAuth flows

### `/core/report_generator.py` - Output Formatting (36KB)

Formats scan results into various output formats:
- `raw`: Raw JSON output
- `summary`: High-level summary
- `detailed`: Detailed findings
- `table`: Tabular format
- `by_tool`: Grouped by tool
- `by_analyzer`: Grouped by analyzer
- `by_severity`: Grouped by severity

## Analyzers Deep Dive

### Base Analyzer (`core/analyzers/base.py`)

**Purpose**: Abstract base class for all analyzers

**Key Classes**:
- **`SecurityFinding`**: Core data structure for all findings
  - Severity levels: `HIGH`, `MEDIUM`, `LOW`, `SAFE`, `UNKNOWN`
  - Auto-enriches with MCP Taxonomy via `ThreatMapping`
  - Normalizes and validates all inputs
  - Maps analyzer names to taxonomy keys: `LLM`, `YARA`, `API`, `BEHAVIORAL`

**`BaseAnalyzer` Interface**:
```python
class BaseAnalyzer(ABC):
    @abstractmethod
    async def analyze(self, content: str, context: Dict[str, Any]) -> List[SecurityFinding]:
        pass
```

**Constraints**:
- All analyzers MUST inherit from `BaseAnalyzer`
- All analyzers MUST implement `analyze()` method
- `analyze()` MUST be async
- `analyze()` MUST return `List[SecurityFinding]`
- Empty list = no findings (safe)

### Behavioral Analyzer (`core/analyzers/behavioral/`)

**File**: `code_analyzer.py` (19KB)

**Purpose**: Detects description-code mismatches using LLM-powered semantic analysis

**How It Works**:
1. Extracts MCP-decorated functions with docstrings via AST parsing
2. Builds interprocedural call graph for entire codebase
3. Extracts rich code context (dataflow, taint, constants)
4. Sends function + context to LLM for alignment verification
5. Maps findings to MCP taxonomy

**Key Components**:
- `BehavioralCodeAnalyzer`: Main orchestrator
- `AlignmentOrchestrator`: LLM communication manager
- `ContextExtractor`: Code context extraction
- `CallGraphAnalyzer`: Cross-file call graph builder

**Constraints**:

1. **File Size Limits**:
   - `MAX_FILE_SIZE_BYTES`: 1MB default (env: `MCP_SCANNER_MAX_FILE_SIZE_BYTES`)
   - `MAX_FUNCTION_SIZE_BYTES`: 50KB default (env: `MCP_SCANNER_MAX_FUNCTION_SIZE_BYTES`)
   - Files exceeding limits are skipped with warning

2. **Context Extraction Limits** (to control prompt size):
   - `BEHAVIORAL_MAX_OPERATIONS_PER_PARAM`: 10 operations per parameter
   - `BEHAVIORAL_MAX_FUNCTION_CALLS`: 20 function calls tracked
   - `BEHAVIORAL_MAX_ASSIGNMENTS`: 15 assignments tracked
   - `BEHAVIORAL_MAX_CROSS_FILE_CALLS`: 10 cross-file calls
   - `BEHAVIORAL_MAX_REACHABLE_FILES`: 5 reachable files
   - `BEHAVIORAL_MAX_CONSTANTS`: 10 constants
   - `BEHAVIORAL_MAX_STRING_LITERALS`: 15 string literals
   - `BEHAVIORAL_MAX_REACHES_CALLS`: 10 reachability calls

3. **LLM Requirements**:
   - API key REQUIRED: `MCP_SCANNER_LLM_API_KEY`
   - Model REQUIRED: `MCP_SCANNER_LLM_MODEL` (default: `gpt-4o`)
   - Optional: `MCP_SCANNER_LLM_BASE_URL`, `MCP_SCANNER_LLM_API_VERSION`
   - Timeout: 30s default (env: `MCP_SCANNER_LLM_TIMEOUT`)
   - Max retries: 3 (env: `MCP_SCANNER_LLM_MAX_RETRIES`)

4. **Directory Scanning**:
   - Only processes `.py` files
   - Skips `__pycache__` and hidden directories (`.`)
   - Sorted file processing for deterministic results

5. **Performance**:
   - Each MCP function = 1 LLM API call
   - Large codebases can take minutes to hours
   - Cost scales with number of functions

**Error Handling**:
- Continues analysis if individual files fail
- Logs warnings for skipped files
- Returns empty list on catastrophic failure

### API Analyzer (`core/analyzers/api_analyzer.py`)

**File**: `api_analyzer.py` (7KB)

**Purpose**: Integrates with Cisco AI Defense API for threat detection

**How It Works**:
1. Constructs API request with content and enabled rules
2. Sends POST request to Cisco AI Defense endpoint
3. Parses `is_safe` and `classifications` from response
4. Maps classifications to MCP taxonomy and creates findings

**Enabled Rules** (8 threat categories):
- Prompt Injection
- Harassment
- Hate Speech
- Profanity
- Sexual Content & Exploitation
- Social Division & Polarization
- Violence & Public Safety Threats
- Code Detection

**Constraints**:

1. **API Key Requirement**:
   - REQUIRED: `MCP_SCANNER_API_KEY` environment variable
   - Passed via `X-Cisco-AI-Defense-API-Key` header
   - No default value - must be explicitly configured

2. **Endpoint Configuration**:
   - Default: `https://us.api.inspect.aidefense.security.cisco.com/api/v1`
   - Configurable via `MCP_SCANNER_ENDPOINT` environment variable
   - Path: `/inspect/chat`

3. **HTTP Configuration**:
   - Timeout: 30s default (env: `MCP_SCANNER_HTTP_TIMEOUT`)
   - Method: POST with JSON payload
   - Content-Type: `application/json`

4. **Content Constraints**:
   - Empty/None content returns empty findings (no API call)
   - Content size limited by API payload limits
   - No explicit size validation in analyzer

5. **Network & Rate Limits**:
   - Requires internet connectivity
   - Subject to Cisco AI Defense API rate limits
   - No built-in retry logic (fails on first error)

**Error Handling**:
- Raises `httpx.HTTPError` on API failures (no retry)
- Logs warnings for empty content
- Does not catch or suppress exceptions

**Threat Mapping**:
- Uses `API_THREAT_MAPPING` to map classifications to MCP taxonomy
- Generates summary with threat count and names
- Enriches findings with severity and taxonomy

### LLM Analyzer (`core/analyzers/llm_analyzer.py`)

**File**: `llm_analyzer.py` (24KB, 580 lines)

**Purpose**: Uses LLM to analyze code/prompts for security risks

**Supported Providers** (via LiteLLM):
- OpenAI (GPT-3.5, GPT-4, GPT-4o)
- Azure OpenAI
- Anthropic (Claude 3 Opus/Sonnet/Haiku)
- Google Gemini
- AWS Bedrock (Claude via Bedrock)
- Any LiteLLM-supported provider

**How It Works**:
1. Loads threat analysis prompt with boilerplate protection rules
2. Generates random delimiter tags for prompt injection defense
3. Constructs analysis prompt with tool name, description, parameters
4. Calls LLM via LiteLLM with retry logic
5. Parses JSON response and maps threats to MCP taxonomy

**Constraints**:

1. **API Key Requirements**:
   - **Non-Bedrock**: `MCP_SCANNER_LLM_API_KEY` REQUIRED
   - **AWS Bedrock**: `MCP_SCANNER_LLM_API_KEY` OR AWS credentials (profile/IAM/session token)
   - No default value - must be explicitly configured

2. **Model Configuration**:
   - Model REQUIRED: `MCP_SCANNER_LLM_MODEL` (default: `gpt-4o`)
   - Optional: `MCP_SCANNER_LLM_BASE_URL` (for custom endpoints)
   - Optional: `MCP_SCANNER_LLM_API_VERSION` (for Azure)

3. **LLM Parameters**:
   - `DEFAULT_LLM_MAX_TOKENS`: 1000 (env: `MCP_SCANNER_DEFAULT_LLM_MAX_TOKENS`)
   - `DEFAULT_LLM_TEMPERATURE`: 0.1 (env: `MCP_SCANNER_DEFAULT_LLM_TEMPERATURE`)
   - `DEFAULT_LLM_TIMEOUT`: 30s (env: `MCP_SCANNER_LLM_TIMEOUT`)
   - `LLM_MAX_RETRIES`: 3 (env: `MCP_SCANNER_LLM_MAX_RETRIES`)
   - `LLM_RETRY_BASE_DELAY`: 1.0s (env: `MCP_SCANNER_LLM_RETRY_BASE_DELAY`)

4. **Prompt Size Limits**:
   - `PROMPT_LENGTH_THRESHOLD`: 75,000 characters (env: `MCP_SCANNER_PROMPT_LENGTH_THRESHOLD`)
   - Prompts exceeding threshold trigger warnings
   - Must fit within model's context window

5. **Prompt Injection Defense**:
   - Generates random 32-char hex delimiter tags
   - Validates content doesn't contain delimiter tags
   - If detected, creates HIGH severity finding immediately

6. **AWS Bedrock Specific**:
   - Region: `AWS_REGION` (default: `us-east-1`)
   - Supports: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`

**Error Handling**:
- Retries up to 3 times with exponential backoff
- Logs detailed error information
- Returns empty list on catastrophic failure
- Validates JSON response format

**Threat Detection**:
- Analyzes tool name, description, parameters
- Detects: code execution, data exfiltration, injection attacks, SSRF, etc.
- Returns severity (HIGH/MEDIUM/LOW) and threat categories
- Maps to MCP taxonomy via `LLM_THREAT_MAPPING`

### YARA Analyzer (`core/analyzers/yara_analyzer.py`)

**File**: `yara_analyzer.py` (8KB, 199 lines)

**Purpose**: Pattern-based detection using YARA rules

**How It Works**:
1. Loads and compiles all `.yara`/`.yar` files from rules directory
2. Matches content against compiled YARA rules
3. Extracts metadata (description, classification, threat_type) from matches
4. Maps threat_type to MCP taxonomy via `YARA_THREAT_MAPPING`
5. Creates SecurityFinding for each match with severity and category

**Constraints**:

1. **Rules Directory**:
   - Default: `mcpscanner/data/yara_rules/` (env: `MCP_SCANNER_YARA_RULES_DIR`)
   - Custom: Specify via `rules_dir` parameter in constructor
   - MUST exist and contain at least one `.yara` or `.yar` file
   - Raises `FileNotFoundError` if missing or empty

2. **Rule File Format**:
   - Extensions: `.yara` or `.yar` (env: `MCP_SCANNER_YARA_RULES_EXT`)
   - Must be valid YARA syntax
   - All rules compiled together at initialization
   - Syntax error in ANY rule = failure for ALL rules

3. **Rule Metadata** (extracted from matches):
   - `description`: Human-readable description of threat
   - `classification`: Threat classification category
   - `threat_type`: Maps to MCP taxonomy (REQUIRED for proper mapping)
   - Missing metadata = "unknown" classification

4. **Performance Characteristics**:
   - Fast: No network calls, no LLM costs
   - Deterministic: Same input = same output
   - Synchronous: No async operations
   - Suitable for large-scale scanning

5. **Content Constraints**:
   - Empty/None content returns empty findings (no matching)
   - No explicit size limits
   - Matches on string data only

6. **Accuracy Limitations**:
   - Only detects known patterns defined in rules
   - Cannot detect novel or zero-day threats
   - Prone to false positives if rules too broad
   - Requires regular rule updates for new threats

**Threat Mapping**:
- Uses `YARA_THREAT_MAPPING` to map `threat_type` to MCP taxonomy
- Includes severity (HIGH/MEDIUM/LOW) from mapping
- Falls back to "UNKNOWN" severity if threat_type not in mapping

**Error Handling**:
- Validates rules directory exists at initialization
- Logs all loaded rule files for debugging
- Raises `yara.Error` on compilation failure (with details)
- Raises exception on analysis failure (does not suppress)
- Returns empty list for empty content (no error)

**Best Practices**:
- Include `threat_type` metadata in all rules for proper taxonomy mapping
- Keep rules specific to minimize false positives
- Test rules against known good/bad samples before deployment
- Update rules regularly for emerging threat patterns

## CLI (`cli.py`) - 1500+ Lines

**Purpose**: Command-line interface with multiple subcommands

**Subcommands**:
- `remote`: Scan remote MCP server via HTTP/SSE
- `prompts`: Scan MCP prompts on a server
- `resources`: Scan MCP resources on a server
- `instructions`: Scan server instructions
- `behavioral`: Scan local source code for behavioral issues
- `stdio`: Scan MCP server via stdio (local command)
- `config`: Scan servers from MCP config file
- `known-configs`: Scan well-known config locations

**Global Flags** (must come before subcommand):
- `--analyzers`: Select analyzers (api, yara, llm, behavioral)
- `--output`: Save results to file
- `--format`: Output format (raw, summary, detailed, table, etc.)
- `--detailed`: Show detailed results
- `--verbose`: Verbose output

**Display Functions**:
- `display_prompt_results()`: Format prompt scan results
- `display_resource_results()`: Format resource scan results
- `display_instructions_results()`: Format instructions scan results
- Table and detailed views for each result type

**Important**: Global flags must come BEFORE the subcommand.

## Data Files (`data/`)

### `prompts/` - LLM Prompts

**`code_alignment_threat_analysis_prompt.md`**: Main prompt for behavioral analysis
- Instructs LLM on how to detect mismatches and classify threats
- Includes comprehensive false positive guidance across ALL 14 threat categories
- Core principle: "Legitimate software performs legitimate operations"

### `yara_rules/` - YARA Detection Rules

- Pattern definitions for known threats
- Regular expressions for suspicious code
- Metadata for threat classification

### `taxonomies/` - Threat Classification

- MCP MITRE-style taxonomy
- Threat categories and techniques
- Severity mappings

## Important Implementation Details

### Safety Determination
- `is_safe` is based on severity: `["SAFE", "LOW"]` = safe, others = unsafe
- Fixed in commit to use severity-based logic instead of always False

### Output Handling
- Behavioral subcommand saves output via `args.output`
- Other subcommands use the main output handler
- Supports formats: raw, summary, detailed, table, by_tool, by_analyzer, by_severity

### Behavioral Analysis Flow
1. Uses AST parsing to extract function definitions
2. Sends code + description to LLM for alignment analysis
3. Classifies threats using MCP MITRE-style taxonomy
4. Handles retries for LLM API failures

## Development Guidelines

### Adding a New Analyzer

1. Create new file in `core/analyzers/`
2. Inherit from `BaseAnalyzer`
3. Implement `async def analyze(self, content: str, context: Dict[str, Any]) -> List[SecurityFinding]`
4. Add threat mapping to appropriate taxonomy file
5. Register analyzer in `Scanner` class
6. Add tests in `tests/`

### Modifying Threat Taxonomy

1. Update `data/taxonomies/` files
2. Update threat mappings in analyzer files
3. Update documentation in `docs/mcp-threats-taxonomy.md`
4. Add tests for new threat categories

### Adding New CLI Subcommand

1. Add subparser in `cli.py`
2. Implement handler function
3. Add display function if needed
4. Update help text
5. Add tests

## Common Issues

### LLM Configuration Errors
- Ensure `MCP_SCANNER_LLM_API_KEY` is set
- Verify `MCP_SCANNER_LLM_MODEL` is correct
- Check `MCP_SCANNER_LLM_BASE_URL` for custom endpoints

### YARA Compilation Failures
- Check YARA rule syntax
- Ensure rules directory exists
- Verify all `.yara` files are valid

### API Analyzer Failures
- Verify `MCP_SCANNER_API_KEY` is set
- Check network connectivity
- Verify endpoint URL is correct

---

**Last Updated**: December 2025
**Maintained By**: Cisco AI Defense Team
