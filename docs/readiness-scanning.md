# Readiness Scanning

The Readiness Analyzer is a zero-dependency static analysis engine that checks MCP tools for production readiness issues. It focuses on **operational reliability**, complementing the security-focused analyzers (API, YARA, LLM).

## Overview

While security scanning tells you if a tool is **safe**, readiness scanning tells you if a tool will be **reliable** in production. The Readiness Analyzer detects issues like missing timeouts, unsafe retry loops, silent failures, and overloaded tool scope.

**Key Features:**
- **Zero external dependencies** — Always available, no API keys required
- **20 heuristic rules** — Comprehensive coverage of operational issues
- **Readiness score** — 0-100 numeric score for easy thresholding
- **Production ready flag** — Quick pass/fail assessment

## Quick Start

### Basic Usage

```bash
# Readiness-only scan
mcp-scanner --analyzers readiness --server-url http://localhost:8000/mcp

# Combined security + readiness scan
mcp-scanner --analyzers yara,llm,readiness --server-url http://localhost:8000/mcp

# Readiness scan with detailed output
mcp-scanner --analyzers readiness --detailed --server-url http://localhost:8000/mcp

# Scan stdio server for readiness
mcp-scanner --analyzers readiness stdio --stdio-command uvx --stdio-arg mcp-server-fetch
```

### Programmatic Usage

```python
import asyncio
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

async def main():
    config = Config()
    scanner = Scanner(config)

    # Scan with readiness analyzer
    results = await scanner.scan_remote_server_tools(
        "http://127.0.0.1:8000/mcp",
        analyzers=[AnalyzerEnum.READINESS]
    )

    for result in results:
        print(f"Tool: {result.tool_name}")
        print(f"Safe: {result.is_safe}")

        for finding in result.findings:
            print(f"  [{finding.severity}] {finding.summary}")
            print(f"    Rule: {finding.details.get('rule_id')}")
            print(f"    Score: {finding.details.get('readiness_score')}")
            print(f"    Production Ready: {finding.details.get('is_production_ready')}")

asyncio.run(main())
```

## Heuristic Rules

The Readiness Analyzer implements 20 core heuristic rules:

### Timeout Guards (HEUR-001, HEUR-002)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| HEUR-001 | HIGH | Missing timeout configuration |
| HEUR-002 | MEDIUM | Timeout too long (>5 minutes) |

**Why it matters:** Without timeouts, operations can hang indefinitely when external services become unresponsive, causing cascading failures.

### Retry Configuration (HEUR-003, HEUR-004, HEUR-005)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| HEUR-003 | MEDIUM | No retry limit defined |
| HEUR-004 | HIGH | Unlimited or excessive retries (>10 or -1) |
| HEUR-005 | LOW | Missing backoff strategy |

**Why it matters:** Unsafe retry patterns can cause thundering herd effects, resource exhaustion, and extended outages.

### Error Handling (HEUR-006, HEUR-007, HEUR-008)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| HEUR-006 | MEDIUM | Missing error response schema |
| HEUR-007 | LOW | Error schema missing error code field |
| HEUR-008 | LOW | Missing output schema |

**Why it matters:** Without structured error responses, agents cannot programmatically handle failures.

### Description Quality (HEUR-009, HEUR-010)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| HEUR-009 | MEDIUM | Vague or missing description |
| HEUR-010 | HIGH | Overloaded tool scope (>5 verbs or "any/all/everything") |

**Why it matters:** Poor descriptions confuse agents. Overloaded tools are hard to test, maintain, and use reliably.

### Input Validation (HEUR-011, HEUR-012)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| HEUR-011 | LOW | No required fields specified in input schema |
| HEUR-012 | INFO | Missing input validation hints (pattern, enum, etc.) |

**Why it matters:** Missing validation can lead to runtime errors from invalid inputs.

### Operational Configuration (HEUR-013, HEUR-014, HEUR-015)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| HEUR-013 | LOW | No rate limit configuration |
| HEUR-014 | LOW | Missing version information |
| HEUR-015 | LOW | No observability configuration |

**Why it matters:** Lack of operational config makes production debugging and maintenance difficult.

### Resource Management (HEUR-016, HEUR-017)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| HEUR-016 | MEDIUM | Resource cleanup not documented |
| HEUR-017 | INFO | No idempotency indication for state-changing operations |

**Why it matters:** Resource leaks cause production instability. Non-idempotent retries can cause data duplication.

### Safety (HEUR-018, HEUR-019, HEUR-020)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| HEUR-018 | HIGH | Dangerous operation keywords (delete, drop, exec, eval) |
| HEUR-019 | INFO | No authentication context for external services |
| HEUR-020 | MEDIUM | Circular dependency risk (self-referencing) |

**Why it matters:** Destructive operations need extra safeguards. Missing auth docs lead to runtime failures.

## Readiness Score

The Readiness Analyzer calculates a numeric score (0-100) based on findings:

| Severity | Points Deducted |
|----------|-----------------|
| CRITICAL | -25 |
| HIGH | -15 |
| MEDIUM | -8 |
| LOW | -3 |
| INFO | -1 |

### Production Ready Criteria

A tool is considered **production ready** when:
- Readiness score ≥ 70
- No CRITICAL severity findings

### Score Grades

| Score | Grade |
|-------|-------|
| 90-100 | Excellent |
| 80-89 | Good |
| 70-79 | Acceptable |
| 50-69 | Poor |
| 0-49 | Critical |

## Threat Taxonomy

Readiness findings map to the following operational risk categories:

| Threat Category | AITech | Description |
|-----------------|--------|-------------|
| MISSING_TIMEOUT_GUARD | AITech-OP-1.1 | Operations may hang indefinitely |
| UNSAFE_RETRY_LOOP | AITech-OP-1.2 | Retry logic may cause resource exhaustion |
| SILENT_FAILURE_PATH | AITech-OP-2.1 | Errors not properly surfaced |
| MISSING_ERROR_SCHEMA | AITech-OP-2.2 | No structured error responses |
| OVERLOADED_TOOL_SCOPE | AITech-OP-3.1 | Too many capabilities |
| NO_OBSERVABILITY_HOOKS | AITech-OP-4.1 | Missing logging/metrics/tracing |
| NON_DETERMINISTIC_RESPONSE | AITech-OP-5.1 | Unpredictable response format |

## Output Examples

### Summary Format

```bash
mcp-scanner --analyzers readiness --format summary --server-url http://localhost:8000/mcp
```

```
=== MCP Scanner Summary ===

Scan Target: http://localhost:8000/mcp

Tools Scanned: 3
  Safe: 1
  Unsafe: 2

Severity Breakdown:
  HIGH: 2
  MEDIUM: 4
  LOW: 3
  INFO: 1
```

### Detailed Format

```bash
mcp-scanner --analyzers readiness --detailed --server-url http://localhost:8000/mcp
```

```
=== MCP Scanner Detailed Results ===

Tool: execute_query
Status: completed
Safe: No
Findings:
  • [HIGH] HEUR-001: Tool 'execute_query' does not specify a timeout.
    Category: MISSING_TIMEOUT_GUARD
    Readiness Score: 55
    Production Ready: No

  • [MEDIUM] HEUR-003: Tool 'execute_query' does not specify a retry limit.
    Category: UNSAFE_RETRY_LOOP
```

## Combining with Security Analyzers

For comprehensive coverage, combine readiness with security analyzers:

```bash
# Full scan: security + readiness
mcp-scanner --analyzers api,yara,llm,readiness --server-url http://localhost:8000/mcp

# YARA + Readiness (fast, no API keys needed)
mcp-scanner --analyzers yara,readiness --server-url http://localhost:8000/mcp
```

## CI/CD Integration

Use readiness scanning in your CI pipeline:

```yaml
# GitHub Actions example
- name: MCP Readiness Check
  run: |
    mcp-scanner --analyzers readiness --format raw \
      --server-url ${{ env.MCP_SERVER_URL }} \
      --output readiness-results.json

    # Fail if any HIGH severity findings
    if grep -q '"severity": "HIGH"' readiness-results.json; then
      echo "::error::Readiness check failed with HIGH severity findings"
      exit 1
    fi
```

## Credits

The Readiness Analyzer was contributed by Nik Kale, ported from the [MCP Readiness Scanner](https://github.com/nik-kale/mcp-readiness-scanner) project.

