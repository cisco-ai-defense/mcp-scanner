# PyPI Package Scanning

The PyPI package scanner downloads Python packages from PyPI, extracts the source, and runs behavioral analysis. Two execution modes:

- **Docker mode (default, recommended):** the package is downloaded and scanned inside an isolated `mcp-scanner-pypi` container. Untrusted code never touches the host filesystem outside that container.
- **Local (SDK) mode (opt-in via `--no-docker` / `use_docker=False`):** for SDK and CI environments where Docker isn't available. The package archive is downloaded to a temp dir, extracted via `tarfile.extractall(filter="data")` (which rejects symlinks / absolute paths / `..` traversal), bounded by hard size and file-count caps, and analysed in-process. The package's own code is *never executed* — only parsed. Local mode is a weaker sandbox than Docker; prefer Docker for anything untrusted.

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

### Local mode (no Docker, SDK/CI runners)

```bash
mcp-scanner pypi-scan flask --no-docker
```

Local mode runs the scan in-process. The package archive is downloaded to a temp directory, validated against archive size + file-count caps, extracted with `tarfile`'s `data` filter, and parsed by the behavioral analyzer. No package code is executed.

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

# Docker mode (recommended).
scanner = PyPIPackageScanner()
results = scanner.scan_package("flask")
print(f"Safe: {results['is_safe']}, Findings: {results['total_findings']}")

# Specific version
results = scanner.scan_package("requests", version="2.31.0")

# Individual findings
for finding in results["findings"]:
    print(f"[{finding['severity']}] {finding['summary']}")

# Local SDK mode — no Docker required. Code from the package is never
# executed; only parsed. Use when Docker is not available (e.g. shared CI
# runners).
sdk_scanner = PyPIPackageScanner(use_docker=False)
results = sdk_scanner.scan_package("flask")
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

### Docker mode (default)

- **No host volume mounts** — the package is downloaded and scanned entirely inside the container. Only JSON results come back via stdout.
- **Source preferred, wheel fallback** — prefers source distributions for full source analysis; falls back to wheels (which still contain `.py` files) if source builds fail.
- **Container auto-removed** — `--rm` ensures the container is deleted after each scan.
- **LLM keys via env vars** — credentials are passed at runtime via `-e` flags, never baked into the image.
- **Bridge networking** — the container has network access (needed for PyPI + LLM calls) but uses the default bridge network, not host networking.

### Local (no-Docker) mode

- **No package execution.** Local mode parses sources; it never runs `setup.py`, `pip install`, or any code from the downloaded package.
- **HTTPS-only download** to a private temp directory the scanner owns and cleans up.
- **Archive size cap** (`MCP_SCANNER_PACKAGE_ARCHIVE_MAX_BYTES`, default 50 MB) enforced both via `Content-Length` and streaming byte count.
- **Extraction caps**: `MCP_SCANNER_PACKAGE_EXTRACTED_MAX_BYTES` (default 200 MB) and `MCP_SCANNER_PACKAGE_EXTRACTED_MAX_FILES` (default 10 000).
- **`tarfile.extractall(filter="data")`** (Python 3.12+) rejects symlinks, hardlinks, absolute paths, parent traversal, device files, and setuid/setgid members.

Docker is still the recommended path for untrusted packages. Local mode exists for SDK consumers (CI, sandboxed runners) where Docker isn't available — it's a smaller blast radius than `pip install`, but a weaker boundary than a container.

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
  "scan_status": "completed",
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

`scan_status` is one of:

| Value       | Meaning                                                                                          |
|-------------|--------------------------------------------------------------------------------------------------|
| `completed` | Scan ran end-to-end. `is_safe` is `true`/`false` based on `total_findings`.                      |
| `error`     | Scan could not be trusted. `is_safe` is `null`. Either it aborted before findings could be produced (then `error` / `error_code` are present), or every function failed to analyse (e.g. the LLM was unreachable) so a zero-finding result must not be reported as safe. |
| `skipped`   | Reserved for future use (e.g. unsupported package format).                                       |

### Error reporting

When `scan_status == "error"`, the JSON also includes `error` (human-readable message) and `error_code` (stable machine-readable token). SDK / CLI callers branch on `error_code` to surface typed exceptions and exit codes:

| `error_code`                  | Mapped Python exception          | CLI exit code | Notes                                                              |
|-------------------------------|----------------------------------|---------------|--------------------------------------------------------------------|
| `llm_not_configured`          | `LLMNotConfiguredError`          | `2`           | `MCP_SCANNER_LLM_API_KEY` (or `LLM_API_KEY` inside Docker) unset.  |
| `package_download_failed`     | `PyPIScanError`                  | `1`           | HTTPS/host/integrity failure during tarball fetch.                 |
| `package_extraction_failed`   | `PyPIScanError`                  | `1`           | Archive failed traversal / size / file-count caps.                 |
| `scan_failed`                 | `PyPIScanError`                  | `1`           | Catch-all (analyzer crash, unexpected internal error).             |

The contract is identical between Docker and SDK modes, so code paths that handle one work for both.
