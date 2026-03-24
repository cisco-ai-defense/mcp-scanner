# Vulnerable Packages Scanning

The Vulnerable Packages Analyzer scans Python dependencies for known security vulnerabilities using [pip-audit](https://github.com/pypa/pip-audit). It identifies packages with published CVEs, PYSEC advisories, and GHSA entries, and maps each finding to the Cisco AI Threat Security Taxonomy.

## Overview

This analyzer runs `pip-audit` as a subprocess, parses its JSON output, and converts each vulnerability into a `SecurityFinding` with full taxonomy metadata. It requires no API keys — only the `pip-audit` binary, which is installed automatically with the scanner.

### Key Features

- Scans requirements files (`requirements.txt`, `*.in`), project directories, or installed environments
- Queries PyPI or OSV vulnerability databases
- Reports vulnerability IDs, aliases (CVE/GHSA), fix versions, and full descriptions
- Maps all findings to **AITech-9.2 / AISubtech-9.2.1 (Supply Chain Compromise)**
- Optional auto-fix mode to upgrade vulnerable packages

## Prerequisites

- Python 3.11+
- `pip-audit` — the analyzer auto-discovers it using the following priority:
  1. **Venv binary** — `pip-audit` in the same virtual environment as mcp-scanner (highest priority)
  2. **System PATH** — `pip-audit` found via `$PATH`
  3. **uvx** — runs `uvx pip-audit` (uv's tool runner, no install needed)
  4. **uv tool run** — runs `uv tool run pip-audit` as a fallback when `uvx` isn't on PATH

If you installed mcp-scanner with `pip` or `uv pip install`, pip-audit is included automatically. If you use `uv` as your package manager, the analyzer works out of the box — even without pip-audit installed locally — by falling back to `uvx`.

To verify it's available:

```bash
# Standard install
pip-audit --version

# Or via uv
uvx pip-audit --version
```

## CLI Usage

The `vulnerable-packages` subcommand scans a target path for vulnerable Python dependencies.

### Basic Scanning

```bash
# Scan a requirements file
mcp-scanner vulnerable-packages /path/to/requirements.txt

# Scan a project directory (auto-detects requirements.txt or pyproject.toml)
mcp-scanner vulnerable-packages /path/to/project/

# Scan a constraints file
mcp-scanner vulnerable-packages /path/to/constraints.in
```

### Vulnerability Service

By default, the analyzer queries PyPI. You can switch to the OSV database:

```bash
# Use OSV vulnerability service
mcp-scanner vulnerable-packages /path/to/requirements.txt --vulnerability-service osv
```

### Output Formats

```bash
# Summary (default)
mcp-scanner vulnerable-packages /path/to/requirements.txt --format summary

# Detailed with full findings
mcp-scanner vulnerable-packages /path/to/requirements.txt --format detailed

# Raw JSON
mcp-scanner vulnerable-packages /path/to/requirements.txt --format raw

# Group by severity
mcp-scanner vulnerable-packages /path/to/requirements.txt --format by_severity

# Table format
mcp-scanner vulnerable-packages /path/to/requirements.txt --format table
```

### Saving Results

```bash
# Save JSON results to file
mcp-scanner vulnerable-packages /path/to/requirements.txt --output results.json --format raw

# Verbose output with save
mcp-scanner vulnerable-packages /path/to/requirements.txt --output results.json --verbose
```

### Auto-Fix Mode

```bash
# Automatically upgrade vulnerable packages
mcp-scanner vulnerable-packages /path/to/requirements.txt --fix
```

## Configuration

The analyzer can be configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SCANNER_VULNERABLE_PACKAGES_SERVICE` | `pypi` | Vulnerability service (`pypi` or `osv`) |
| `MCP_SCANNER_VULNERABLE_PACKAGES_TIMEOUT` | `120` | Subprocess timeout in seconds |

## How It Works

### Scan Targets

The analyzer uses the following heuristics to determine how to scan a path:

1. **File ending in `.txt` or `.in`**: Treated as a requirements file (`pip-audit -r <path>`)
2. **Directory with `requirements.txt`**: Scans the requirements file
3. **Directory with `pyproject.toml`**: Scans the project environment. If a `.venv` directory exists, uses `--path .venv`; otherwise uses `--path <directory>`
4. **Other directories**: Uses `--path <directory>` to scan installed packages

### Finding Structure

Each vulnerability produces a `SecurityFinding` with:

- **severity**: `HIGH` if a fix is available, `MEDIUM` otherwise
- **summary**: Human-readable description including package name, version, vulnerability ID, aliases, fix versions, and full description
- **analyzer**: `VULNERABLE_PACKAGES`
- **threat_category**: `VULNERABLE DEPENDENCY`
- **details**: Structured data including:
  - `package_name`, `installed_version`
  - `vulnerability_id` (e.g., `PYSEC-2019-179`)
  - `fix_versions` (e.g., `["1.0", "1.0.1"]`)
  - `aliases` (e.g., `["CVE-2019-1010083", "GHSA-5wv5-4vpf-pj6m"]`)
  - `description` (full vulnerability description)
  - `remediation` (actionable upgrade or monitoring guidance)
  - `references` (links to OSV vulnerability database)
  - Taxonomy fields (`aitech`, `aisubtech`, etc.)

## Threat Taxonomy Mapping

All findings from the Vulnerable Packages Analyzer are mapped to:

| Field | Value |
|-------|-------|
| AITech | AITech-9.2 |
| AITech Name | Detection Evasion |
| AISubtech | AISubtech-9.2.1 |
| AISubtech Name | Supply Chain Compromise |
| Description | A Python dependency with a publicly known vulnerability (CVE/PYSEC/GHSA) was detected. Vulnerable dependencies in MCP server packages can be exploited to compromise the server, exfiltrate data, or escalate privileges. |

## Example Output

### Scanning a Vulnerable Requirements File

Given a `requirements.txt` containing:

```
flask==0.5
jinja2==2.10
```

Running:

```bash
mcp-scanner vulnerable-packages requirements.txt --format detailed
```

Produces output listing each vulnerable package with its vulnerability IDs, aliases, fix versions, and full descriptions. Packages without known vulnerabilities are reported as safe.

### JSON Output Structure

```json
[
  {
    "tool_name": "flask==0.5",
    "tool_description": "PYSEC-2019-179: flask==0.5 | Aliases: CVE-2019-1010083, GHSA-5wv5-4vpf-pj6m | Flask before 1.0 is affected by unexpected memory usage...",
    "status": "completed",
    "is_safe": false,
    "findings": {
      "vulnerable_packages_analyzer": {
        "severity": "HIGH",
        "threat_summary": "Vulnerable dependency: flask==0.5 [PYSEC-2019-179] | Aliases: CVE-2019-1010083, GHSA-5wv5-4vpf-pj6m | Fix: 1.0 | Details: ...",
        "threat_names": ["VULNERABLE DEPENDENCY"],
        "total_findings": 1,
        "mcp_taxonomies": [
          {
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.1",
            "aisubtech_name": "Supply Chain Compromise",
            "description": "A Python dependency with a publicly known vulnerability..."
          }
        ]
      }
    }
  }
]
```

## Programmatic Usage

```python
from mcpscanner.core.analyzers.vulnerable_packages_analyzer import VulnerablePackagesAnalyzer

analyzer = VulnerablePackagesAnalyzer(
    enabled=True,
    vulnerability_service="pypi",
    timeout=120,
)

# Scan a requirements file
findings = analyzer.analyze_requirements("/path/to/requirements.txt")

# Or scan a project directory
findings = analyzer.analyze_path("/path/to/project/")

# Inspect findings
for finding in findings:
    print(f"{finding.severity}: {finding.summary}")
    print(f"  Package: {finding.details['package_name']}=={finding.details['installed_version']}")
    print(f"  Vuln ID: {finding.details['vulnerability_id']}")
    print(f"  Fix: {finding.details['fix_versions']}")
    print(f"  Remediation: {finding.details['remediation']}")

# Access scan summary
if analyzer.last_scan_summary:
    summary = analyzer.last_scan_summary
    print(f"Total packages: {summary['total_packages']}")
    print(f"Vulnerable: {summary['vulnerable_packages']}")
    print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
```
