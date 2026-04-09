# MCP Schema Linter — Design Document

## Motivation

MCP-scanner focuses on security and vulnerability scanning, but there is no quality validation step to catch MCP schema issues early (missing descriptions, inconsistent naming, incomplete documentation, structural gaps). Without early validation, these issues surface late — during agent execution, integration testing, or code review.

Based on patterns from API ecosystems (Spectral for OpenAPI, vacuum), a linting-style validator surfaces quality and correctness issues before runtime.

## Architecture

The linter is a self-contained module under `mcpscanner/core/analyzers/linter/` with its own finding type and output formatter. It connects to MCP servers using the existing MCP SDK but runs a separate validation pipeline.

### Components

```
mcpscanner/core/analyzers/linter/
├── __init__.py       # Public API exports
├── engine.py         # LintEngine: orchestrates rules, collects findings
├── finding.py        # LintFinding, LintSeverity, LintSummary data classes
├── rule.py           # LintRule ABC, RuleRegistry
├── formatter.py      # Table/JSON/summary output formatters
├── rulesets.py       # Predefined rulesets (recommended, strict, quality)
├── config.py         # YAML config loader for rule overrides
└── rules/            # Built-in rules grouped by category
    ├── tool_rules.py
    ├── prompt_rules.py
    ├── resource_rules.py
    └── server_rules.py
```

### Data Flow

1. CLI parses `lint` subcommand arguments
2. MCP connection established (remote/stdio) or static files loaded
3. Tool/prompt/resource schemas converted to plain dicts
4. `LintEngine` runs active rules from `RuleRegistry` against each item
5. Server-level rules run against the aggregate
6. Findings sorted by severity, summarized into `LintSummary`
7. `LintFormatter` renders output (table, summary, or JSON)

## Design Decisions

### Standalone finding type vs SecurityFinding

The linter uses `LintFinding` instead of `SecurityFinding` because:
- Lint findings have different semantics (quality, not security)
- Different severity levels (error/warning/info/hint vs HIGH/MEDIUM/LOW)
- Different output format requirements (rule ID, recommendation, affected items)
- Clean separation avoids overloading security reporting pipelines

### Rule architecture

Rules follow the declarative pattern from `prompt_defense_analyzer.py`:
- Each rule is a class extending `LintRule` with a `check()` method
- Rules are stateless and produce `LintFinding` lists
- A `RuleRegistry` manages enable/disable and severity overrides
- Severity overrides are applied on copies to avoid shared state mutation

### Rulesets

Three predefined rulesets cover different use cases:
- `recommended`: sensible defaults for development
- `strict`: CI enforcement (info promoted to warning)
- `quality`: documentation-focused subset

### 37 rules

Rules are grouped by the MCP concept they validate:
- 18 tool rules (schema structure, naming, documentation)
- 8 prompt rules (metadata, arguments)
- 6 resource rules (URI, MIME type, naming)
- 5 server rules (uniqueness, capabilities, limits)

## Integration Points

| Area | What was added |
|------|----------------|
| `AnalyzerEnum` | `LINT = "lint"` in `models.py` |
| Package exports | `LintEngine` in `analyzers/__init__.py` |
| CLI | `lint` subparser in `cli.py` with dedicated handler |
| MCP connection | Reuses MCP SDK directly for schema fetching |

## Testing

178 unit tests organized by component:
- Per-rule tests (tool, prompt, resource, server)
- Engine orchestration tests (rulesets, summary accuracy)
- Formatter tests (table, summary, JSON output)
- CLI integration tests (static file linting, ruleset behavior)

## Future Work

- Additional rules for MCP-specific patterns (e.g., timeout/retry metadata)
- Integration with readiness analyzer for cross-cutting validation
- Custom rule plugins loaded from external packages
- IDE integration (LSP-based real-time linting)
