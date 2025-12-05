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
7. 
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

**Evaluation Process**:
1. Scan multiple MCP servers from repository list
2. Classify findings as TP (true positive) or FP (false positive)
3. Calculate precision, recall, F1 score
4. Generate detailed CSV reports
5. Compare results across different runs

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

### Generated/Runtime Directories

- **`logs/`**: Scan result logs (gitignored)
- **`latest_logs/`**: Latest scan results (gitignored)
- **`cloned/`**: Cloned repositories for evaluation (gitignored)
- **`.venv/`**: Virtual environment (gitignored)
- **`__pycache__/`**: Python bytecode cache (gitignored)

## Key Technologies

- **Language**: Python 3.11+
- **Package Manager**: uv (fast Python package manager)
- **MCP SDK**: Model Context Protocol for server communication
- **LLM Integration**: Azure OpenAI, OpenAI, Anthropic, Google Gemini
- **Analysis**: AST parsing, pattern matching, semantic analysis

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
