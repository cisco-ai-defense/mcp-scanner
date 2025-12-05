# AGENTS.md

This file provides comprehensive context and instructions for AI coding agents working on the MCP Scanner project.

## Project Overview

**MCP Scanner** is a comprehensive security analysis tool for Model Context Protocol (MCP) servers. It identifies security vulnerabilities, behavioral mismatches, and potential threats in MCP server implementations through multiple analysis techniques including LLM-powered semantic analysis, pattern matching, and API-based threat detection.

### What is MCP?

The Model Context Protocol (MCP) is an open protocol that enables AI applications to securely connect to external data sources and tools. MCP servers expose tools, prompts, and resources that AI agents can use. However, these servers can contain security vulnerabilities or malicious behavior that could compromise AI systems.

### Why MCP Scanner?

MCP Scanner addresses the critical need for security analysis in the MCP ecosystem by:
- **Detecting Hidden Threats**: Identifies malicious behavior not obvious from descriptions
- **Preventing Tool Poisoning**: Finds description-code mismatches that could trick AI agents
- **Identifying Vulnerabilities**: Discovers code execution, injection attacks, and data exfiltration risks
- **Enabling Safe Adoption**: Helps developers and organizations safely use MCP servers

### Key Capabilities

1. **Behavioral Analysis**: Detects description-code mismatches and hidden malicious behavior using LLM-powered semantic analysis
2. **LLM-Powered Threat Detection**: Uses AI to analyze code for security risks with MITRE-style taxonomy
3. **YARA Pattern Matching**: Identifies known malicious patterns and suspicious code constructs
4. **API-Based Classification**: Leverages Cisco AI Defense for threat detection and classification
5. **Multiple Scan Modes**: Remote servers, local source code, stdio servers, config files, prompts, resources, instructions
6. **Comprehensive Reporting**: Detailed findings with severity levels, threat categories, and remediation guidance


## Project Structure

```
mcp-scanner/
├── mcpscanner/              # Core scanner implementation
│   ├── core/               # Scanner engine and analysis components
│   │   ├── analyzers/      # Security analyzers
│   │   │   ├── behavioral/ # Behavioral analysis (description-code mismatch)
│   │   │   ├── api.py      # Cisco AI Defense API analyzer
│   │   │   ├── llm.py      # LLM-powered threat detection
│   │   │   └── yara.py     # YARA pattern matching
│   │   ├── static_analysis/ # Static code analysis utilities
│   │   ├── scanner.py      # Main scanner orchestration
│   │   ├── result.py       # Result data structures
│   │   ├── models.py       # Data models for findings
│   │   ├── auth.py         # Authentication handling
│   │   └── report_generator.py # Output formatting
│   ├── api/                # API client implementations
│   ├── config/             # Configuration management
│   ├── data/               # Static data files
│   │   ├── prompts/        # LLM prompts for analysis
│   │   ├── yara_rules/     # YARA detection rules
│   │   └── taxonomies/     # Threat classification taxonomies
│   ├── threats/            # Threat definitions
│   ├── utils/              # Utility functions
│   ├── cli.py              # Command-line interface (1500+ lines)
│   └── server.py           # MCP server implementation
├── tests/                  # Comprehensive test suite
│   ├── test_behavioral_analyzer.py
│   ├── test_scanner.py
│   ├── test_instructions_scanning.py
│   └── ... (40+ test files)
├── examples/               # Usage examples and demos
│   ├── scan_instructions_example.py
│   ├── programmatic_exception_handling.py
│   └── ... (40+ examples)
├── evals/                  # Evaluation framework
│   ├── behavioral-analysis/ # Behavioral scan evaluations
│   │   ├── scripts/        # Evaluation scripts
│   │   └── results/        # Evaluation results
│   └── README.md           # Evaluation documentation
├── docs/                   # Comprehensive documentation
│   ├── architecture.md     # System architecture
│   ├── behavioral-scanning.md # Behavioral analysis guide
│   ├── llm-providers.md    # LLM integration guide
│   ├── mcp-threats-taxonomy.md # Threat classification
│   ├── api-reference.md    # API documentation
│   └── ... (12 doc files)
├── .github/                # GitHub workflows and templates
├── pyproject.toml          # Python project configuration
├── uv.lock                 # Dependency lock file
└── README.md               # Project overview

```

## Directory Details

### `/mcpscanner/` - Core Implementation

The main package containing all scanner functionality.

#### `/mcpscanner/core/` - Scanner Engine
- **`scanner.py`** (96KB): Main orchestrator that coordinates all analyzers, handles MCP communication, and manages scan lifecycle. Contains methods for scanning remote servers, stdio servers, local code, prompts, resources, and instructions.
- **`result.py`** (22KB): Data structures for scan results including `ToolScanResult`, `PromptScanResult`, `ResourceScanResult`, `InstructionsScanResult`, and `SecurityFinding`.
- **`models.py`** (11KB): Core data models for findings, threats, and analysis results.
- **`auth.py`** (17KB): Authentication handling for MCP servers (bearer tokens, API keys).
- **`report_generator.py`** (36KB): Formats scan results into various output formats (JSON, table, detailed, by_tool, by_analyzer, by_severity).
- **`mcp_models.py`**: MCP protocol data models.
- **`exceptions.py`**: Custom exception classes.

#### `/mcpscanner/core/analyzers/` - Security Analyzers

**Behavioral Analyzer** (`behavioral/`):
- **Purpose**: Detects description-code mismatches using LLM-powered semantic analysis
- **Components**:
  - `function_extractor.py`: Extracts functions with decorators and docstrings using AST parsing
  - `alignment_analyzer.py`: Compares declared behavior with actual implementation
  - `threat_classifier.py`: Categorizes threats using MCP taxonomy
  - `alignment_response_validator.py`: Validates and parses LLM responses
- **How it works**: Extracts function code and descriptions, sends to LLM for analysis, classifies threats, returns findings with severity and taxonomy

**API Analyzer** (`api.py`):
- Integrates with Cisco AI Defense API for threat detection
- Sends code/prompts for classification
- Returns threat scores and categories

**LLM Analyzer** (`llm.py`):
- Uses LLM to analyze code for security risks
- Supports multiple providers (OpenAI, Azure, Anthropic, Google)
- Provides detailed threat explanations

**YARA Analyzer** (`yara.py`):
- Pattern-based detection using YARA rules
- Identifies known malicious patterns
- Fast and deterministic

#### `/mcpscanner/core/static_analysis/` - Static Analysis
- AST parsing utilities
- Code structure analysis
- Pattern detection helpers

#### `/mcpscanner/cli.py` - Command-Line Interface (67KB)

Comprehensive CLI with multiple subcommands and display functions:

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

#### `/mcpscanner/data/` - Static Data

**`prompts/`**: LLM prompts for analysis
- `code_alignment_threat_analysis_prompt.md`: Main prompt for behavioral analysis
- Instructs LLM on how to detect mismatches and classify threats

**`yara_rules/`**: YARA detection rules
- Pattern definitions for known threats
- Regular expressions for suspicious code

**`taxonomies/`**: Threat classification
- MCP MITRE-style taxonomy
- Threat categories and techniques

#### `/mcpscanner/config/` - Configuration
- Configuration file parsing
- Environment variable handling
- Default settings

#### `/mcpscanner/api/` - API Clients
- Cisco AI Defense API client
- LLM provider clients
- HTTP utilities

#### `/mcpscanner/utils/` - Utilities
- Helper functions
- Common utilities
- Logging setup

### `/tests/` - Test Suite

Comprehensive test coverage with 40+ test files:
- `test_behavioral_analyzer.py`: Behavioral analysis tests
- `test_scanner.py`: Scanner orchestration tests
- `test_instructions_scanning.py`: Instructions scanning tests
- `test_llm_analyzer.py`: LLM analyzer tests
- `test_yara_analyzer.py`: YARA analyzer tests
- Integration tests for end-to-end workflows
- Mock fixtures for external APIs

### `/examples/` - Usage Examples

40+ example scripts demonstrating:
- Programmatic usage of the scanner
- Different scan modes
- Custom analyzer configurations
- Exception handling
- Output processing
- Integration patterns

Key examples:
- `scan_instructions_example.py`: Scanning server instructions
- `programmatic_exception_handling.py`: Error handling patterns
- Various scan mode demonstrations

### `/evals/` - Evaluation Framework

**Purpose**: Systematic evaluation of scanner performance

**`behavioral-analysis/`**:
- **`scripts/`**: Evaluation scripts for batch scanning
  - `run_behavioral_scan.py`: Batch scan multiple repositories
  - Analysis and comparison scripts
- **`results/`**: Evaluation results and metrics
  - Precision/recall calculations
  - False positive analysis
  - Performance benchmarks


**Current Performance**: 95%+ precision on behavioral analysis

### `/docs/` - Documentation

Comprehensive documentation covering all aspects:

- **`architecture.md`**: System design and component interactions
- **`behavioral-scanning.md`**: Behavioral analysis deep dive
- **`llm-providers.md`**: LLM integration guide (OpenAI, Azure, Anthropic, Google)
- **`mcp-threats-taxonomy.md`**: Threat classification system
- **`mcp-security-scoring.md`**: Security scoring methodology
- **`api-reference.md`**: API documentation
- **`authentication.md`**: Authentication mechanisms
- **`output-formats.md`**: Output format specifications
- **`programmatic-usage.md`**: Using scanner as a library
- **`programmatic_exception_handling.md`**: Error handling guide
- **`development.md`**: Development guidelines

### Root Files

- **`pyproject.toml`**: Python project configuration, dependencies, build settings
- **`uv.lock`**: Locked dependencies for reproducible builds
- **`README.md`**: Project overview and quick start
- **`LICENSE`**: Apache 2.0 license
- **`CONTRIBUTING.md`**: Contribution guidelines
- **`CODE_OF_CONDUCT.md`**: Community code of conduct
- **`SECURITY.md`**: Security policy and vulnerability reporting
- **`CODEOWNERS`**: Code ownership for PR reviews
- **`.gitignore`**: Git ignore patterns
- **`.pre-commit-config.yaml`**: Pre-commit hooks configuration



## Analyzer Deep Dive & Constraints

This section provides detailed information about each analyzer's implementation, constraints, and important considerations.

### Base Analyzer (`base.py`)

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

### Behavioral Analyzer (`behavioral/code_analyzer.py`)

**File**: `mcpscanner/core/analyzers/behavioral/code_analyzer.py` (19KB)

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

### API Analyzer (`api_analyzer.py`)

**File**: `mcpscanner/core/analyzers/api_analyzer.py` (7KB)

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

### LLM Analyzer (`llm_analyzer.py`)

**File**: `mcpscanner/core/analyzers/llm_analyzer.py` (24KB, 580 lines)

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

### YARA Analyzer (`yara_analyzer.py`)

**File**: `mcpscanner/core/analyzers/yara_analyzer.py` (8KB, 199 lines)

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

## Key Technologies

- **Language**: Python 3.11+
- **Package Manager**: uv (fast Python package manager)
- **MCP SDK**: Model Context Protocol for server communication
- **LLM Integration**: Azure OpenAI, OpenAI, Anthropic, Google Gemini, AWS Bedrock
- **Analysis**: AST parsing, pattern matching, semantic analysis, dataflow analysis
- **Libraries**: LiteLLM (LLM abstraction), YARA (pattern matching), httpx (HTTP client)

## Development Setup

### Prerequisites
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone <repo>
cd mcp-scanner
uv sync
```

### Environment Variables
```bash
# LLM Configuration (required for behavioral analysis)
MCP_SCANNER_LLM_API_KEY=<your-api-key>
MCP_SCANNER_LLM_BASE_URL=<api-endpoint>
MCP_SCANNER_LLM_MODEL=<model-name>

# Optional: Cisco AI Defense
MCP_SCANNER_API_KEY=<cisco-api-key>
```

## Common Tasks

### Running Scans

```bash
# Behavioral scan (local source code)
uv run mcp-scanner behavioral <path-to-mcp-server>

# Remote server scan
uv run mcp-scanner remote --server-url <url>

# Scan prompts/resources/instructions
uv run mcp-scanner prompts --server-url <url>
uv run mcp-scanner resources --server-url <url>
uv run mcp-scanner instructions --server-url <url>

# Stdio server scan
uv run mcp-scanner stdio --stdio-command <command> --stdio-args <args>

# Config file scan
uv run mcp-scanner config --config-path <path>
uv run mcp-scanner known-configs  # Scan well-known config locations
```

### Running Tests

```bash
# All tests
uv run pytest

# Specific test file
uv run pytest tests/test_behavioral_analyzer.py

# With coverage
uv run pytest --cov=mcpscanner
```

## Code Architecture

### Scanner Flow
1. **Input**: MCP server (remote URL, local path, stdio command, or config file)
2. **Analysis**: Run selected analyzers (behavioral, LLM, YARA, API)
3. **Results**: Aggregate findings with severity, taxonomy, and details
4. **Output**: Display or save results in various formats

### Key Classes

#### `Scanner` (mcpscanner/core/scanner.py)
Main orchestrator that coordinates analyzers and manages scan lifecycle.

```python
scanner = Scanner(config, rules_dir=rules_path)
results = await scanner.scan_remote_server(server_url, analyzers=[...])
```

#### `BehavioralCodeAnalyzer` (mcpscanner/core/analyzers/behavioral/)
Analyzes source code for description-code mismatches using LLM-powered semantic analysis.

Key components:
- `FunctionExtractor`: Extracts functions with decorators and docstrings
- `AlignmentAnalyzer`: Compares descriptions with actual behavior
- `ThreatClassifier`: Categorizes threats using MCP taxonomy

#### `ScanResult` Types (mcpscanner/core/result.py)
- `ToolScanResult`: Results for individual MCP tools
- `PromptScanResult`: Results for MCP prompts
- `ResourceScanResult`: Results for MCP resources
- `InstructionsScanResult`: Results for server instructions

### CLI Structure (mcpscanner/cli.py)

The CLI uses argparse with subcommands:
- Global flags: `--analyzers`, `--output`, `--format`, `--detailed`
- Subcommands: `remote`, `prompts`, `resources`, `instructions`, `behavioral`, `stdio`, `config`, `known-configs`

**Important**: Global flags must come BEFORE the subcommand.

## Important Implementation Details

### Behavioral Analysis
- Uses AST parsing to extract function definitions
- Sends code + description to LLM for alignment analysis
- Classifies threats using MCP MITRE-style taxonomy
- Handles retries for LLM API failures

### Output Handling
- Behavioral subcommand saves output via `args.output` (lines 1279-1284 in cli.py)
- Other subcommands use the main output handler
- Supports formats: raw, summary, detailed, table, by_tool, by_analyzer, by_severity

### Safety Determination
- `is_safe` is based on severity: `["SAFE", "LOW"]` = safe, others = unsafe
- Fixed in commit to use severity-based logic instead of always False

## Common Pitfalls

1. **Missing LLM Configuration**: Behavioral analyzer requires LLM API credentials
2. **Argument Order**: Global flags must come before subcommands
3. **Output Not Saving**: Ensure `--output` flag is used correctly
4. **Import Errors**: Always use `uv run` to ensure correct environment

## Testing Guidelines

### Writing Tests
- Place tests in `tests/` directory
- Use pytest fixtures for common setup
- Mock external API calls (LLM, Cisco AI Defense)
- Test both success and failure cases

### Test Coverage
- Core analyzers: 80%+ coverage required
- CLI: Test all subcommands and flag combinations
- Integration tests: Test end-to-end scan workflows

## Contributing

### Code Style
- Follow PEP 8
- Use type hints
- Add docstrings to public functions
- Keep functions focused and small

### Pull Request Process
1. Create feature branch from `main`
2. Write tests for new functionality
3. Ensure all tests pass
4. Update documentation
5. Submit PR with clear description

### Security Considerations
- Never commit API keys or credentials
- Validate all user inputs
- Sanitize file paths and commands
- Handle sensitive data appropriately

## Evaluation Process

The project includes evaluation scripts in `evals/behavioral-analysis/`:
- Scan multiple repositories in batch
- Compare results across runs
- Calculate precision/recall metrics
- Generate detailed CSV reports


## Useful Commands

```bash
# Format code

# Build package
uv build

# Install locally
uv pip install -e .
```

## Resources

- **MCP Specification**: https://spec.modelcontextprotocol.io/
- **Project Repository**: https://github.com/cisco-ai-defense/mcp-scanner
- **Documentation**: See `docs/` directory
- **Examples**: See `examples/` directory

## Getting Help

- Check existing issues on GitHub
- Review documentation in `docs/`
- Look at examples in `examples/`
- Run with `--help` flag for CLI usage

## Performance Considerations

- Behavioral analysis can be slow for large codebases (uses LLM)
- Use `--analyzers` flag to select specific analyzers
- Consider file count limits for batch scanning (e.g., skip repos with >100 files)
- LLM retries can add latency; adjust timeout settings as needed

---

**Last Updated**: December 2025
**Maintained By**: Cisco AI Defense Team
