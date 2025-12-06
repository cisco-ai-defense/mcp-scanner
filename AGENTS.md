# AGENTS.md

This file provides high-level context and global rules for AI coding agents working on the MCP Scanner project.

**📁 Subdirectory-Specific Guides:**
- [`mcpscanner/AGENTS.md`](mcpscanner/AGENTS.md) - Core implementation details, analyzers, architecture
- [`tests/AGENTS.md`](tests/AGENTS.md) - Testing guidelines and patterns
- [`examples/AGENTS.md`](examples/AGENTS.md) - Example usage patterns
- [`docs/AGENTS.md`](docs/AGENTS.md) - Documentation guidelines

---

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

## Directory Structure

For detailed information about each directory, see the subdirectory-specific AGENTS.md files:

- **`mcpscanner/`** - Core scanner implementation → See [`mcpscanner/AGENTS.md`](mcpscanner/AGENTS.md)
- **`tests/`** - Comprehensive test suite → See [`tests/AGENTS.md`](tests/AGENTS.md)
- **`examples/`** - Usage examples and demos → See [`examples/AGENTS.md`](examples/AGENTS.md)
- **`docs/`** - Documentation → See [`docs/AGENTS.md`](docs/AGENTS.md)
- **`evals/`** - Evaluation framework for scanner performance (95%+ precision)
- **Root files** - `pyproject.toml`, `uv.lock`, `README.md`, etc.

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

## Global Rules & Best Practices

### Code Style
- Follow PEP 8
- Use type hints for all functions
- Add docstrings to public functions and classes
- Keep functions focused and small (<50 lines when possible)
- Use meaningful variable names

### Error Handling
- Never silently swallow exceptions
- Log errors with appropriate context
- Provide helpful error messages to users
- Use custom exceptions for domain-specific errors

### Security Considerations
- **CRITICAL**: Never commit API keys or credentials
- Validate all user inputs
- Sanitize file paths and commands
- Handle sensitive data appropriately
- Use environment variables for secrets

### Testing Requirements
- Write tests for all new functionality
- Mock external API calls (LLM, Cisco AI Defense)
- Test both success and failure cases
- Aim for 80%+ code coverage on core components
- Use pytest fixtures for common setup

### Performance Guidelines
- Be mindful of LLM API costs (each call costs money)
- Use async/await for I/O-bound operations
- Consider file size limits for large codebases
- Add progress indicators for long-running operations
- Cache results when appropriate

## Common Pitfalls

1. **Missing LLM Configuration**: Behavioral analyzer requires LLM API credentials
2. **Argument Order**: Global flags must come before subcommands
3. **Output Not Saving**: Ensure `--output` flag is used correctly
4. **Import Errors**: Always use `uv run` to ensure correct environment

## Evaluation Process

The project includes evaluation scripts in `evals/behavioral-analysis/`:
- Scan multiple repositories in batch
- Compare results across runs
- Calculate precision/recall metrics
- Generate detailed CSV reports

## Useful Commands

```bash
# Format code
uv run ruff format

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
