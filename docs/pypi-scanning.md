# PyPI Package Scanning (Docker-sandboxed)

The PyPI package scanner downloads Python packages from PyPI inside an isolated Docker container, extracts the source code, and runs behavioral analysis. Docker is **mandatory** — untrusted packages are never extracted on the host.

## Prerequisites

- **Docker** installed and running ([Install Docker](https://docs.docker.com/get-docker/))
- **LLM API key** (for behavioral analysis) — set via `MCP_SCANNER_LLM_API_KEY` environment variable

## How It Works

1. **Docker check** — Verifies Docker is installed and running. Exits with an error if not.
2. **Image build** — Builds a lightweight `python:3.13-alpine` based image with `cisco-ai-mcp-scanner` pre-installed. Cached after first build.
3. **Package download** — Inside the container, downloads the package from PyPI. Prefers source distributions; falls back to wheels if source is unavailable.
4. **Extraction** — Extracts the archive (`.tar.gz`, `.zip`, or `.whl`) to get the Python source files.
5. **Behavioral analysis** — Scans all `.py` files for docstring-vs-code mismatches using LLM-based analysis. Detects hidden behaviors like data exfiltration, backdoors, and prompt injection.
6. **Results** — JSON results are returned to the host via stdout.

## CLI Usage

### Basic scan (latest version)

```bash
mcp-scanner pypi-scan flask
```

### Scan a specific version

```bash
mcp-scanner pypi-scan requests --version 2.31.0
```

### Save results to file

```bash
mcp-scanner pypi-scan fastapi -o results.json --format detailed
```

### Table format

```bash
mcp-scanner pypi-scan flask --format table
```

### Raw JSON output

```bash
mcp-scanner pypi-scan flask --raw
```

### Force rebuild the Docker image

```bash
mcp-scanner pypi-scan flask --rebuild-image
```

### All options

```bash
mcp-scanner pypi-scan <package> [--version VERSION] [--output FILE]
                                [--format {raw,summary,detailed,by_tool,by_analyzer,by_severity,table}]
                                [--verbose] [--raw] [--rebuild-image]
                                [--severity-filter {all,high,medium,low,safe}]
                                [--tool-filter PATTERN] [--hide-safe] [--stats]
```

Global flags like `--severity-filter`, `--tool-filter`, `--analyzer-filter`, `--hide-safe`, and `--stats` work with `pypi-scan` just as with any other subcommand.

## SDK Usage

```python
from mcpscanner.core.pypi_scanner import PyPIPackageScanner

scanner = PyPIPackageScanner()

# Scan latest version
results = scanner.scan_package("flask")
print(f"Safe: {results['is_safe']}")
print(f"Findings: {results['total_findings']}")

# Scan specific version
results = scanner.scan_package("requests", version="2.31.0")

# Access individual findings
for finding in results["findings"]:
    print(f"[{finding['severity']}] {finding['summary']}")
```

See `examples/sdk_pypi_scanner.py` for a complete example.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SCANNER_LLM_API_KEY` | (none) | API key for LLM provider (required for behavioral analysis) |
| `MCP_SCANNER_LLM_MODEL` | `gpt-4o-mini` | LLM model to use |
| `MCP_SCANNER_LLM_BASE_URL` | (none) | Custom base URL for LLM API (e.g., Azure OpenAI endpoint) |
| `MCP_SCANNER_LLM_API_VERSION` | (none) | API version for LLM provider (e.g., `2024-02-15-preview`) |
| `MCP_SCANNER_DOCKER_IMAGE_NAME` | `mcp-scanner-pypi` | Docker image name |
| `MCP_SCANNER_DOCKER_IMAGE_TAG` | `latest` | Docker image tag |
| `MCP_SCANNER_PYPI_SCAN_TIMEOUT` | `300` | Container timeout in seconds |

### Docker Image

The scanner uses a minimal `python:3.13-alpine` image with `cisco-ai-mcp-scanner` installed for behavioral analysis.

The image is built automatically on first use and cached. Use `--rebuild-image` to force a rebuild.

## Security

- **Docker is mandatory** — there is no `--no-docker` or local fallback. PyPI packages may contain malware and must be handled in a sandbox.
- **No host volume mounts** — the package is downloaded and scanned entirely inside the container. Only JSON results come back via stdout.
- **Source preferred, wheel fallback** — prefers source distributions for full source analysis; falls back to wheels (which still contain `.py` files) if source builds fail.
- **Container auto-removed** — the `--rm` flag ensures the container is deleted after the scan completes.
- **LLM keys via env vars** — credentials are passed at runtime via `-e` flags, never baked into the image.
- **Bridge networking** — the container has network access (needed for PyPI download and LLM API calls) but uses the default bridge network, not host networking.

## Output Format

### JSON result structure

```json
{
  "package": "flask",
  "version": "latest",
  "python_files_scanned": 42,
  "total_findings": 1,
  "behavioral_findings": 1,
  "is_safe": false,
  "findings": [
    {
      "analyzer": "behavioral",
      "severity": "HIGH",
      "threat_category": "DATA EXFILTRATION",
      "summary": "Tool sends data to external server",
      "details": {}
    }
  ]
}
```
