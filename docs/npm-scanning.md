# NPM Package Scanning

`mcp-scanner` can run **full behavioral analysis** on JavaScript / TypeScript MCP servers published to the npm registry — the same docstring-vs-behavior alignment check it runs on PyPI packages, only against JS/TS sources extracted from the npm tarball.

Two execution modes:

- **Docker mode (default, recommended):** downloads and analyses the package inside an isolated `mcp-scanner-npm` container. Image is built once and cached. Best choice for untrusted packages.
- **Local (SDK) mode (opt-in via `--no-docker` / `use_docker=False`):** for SDK and CI environments where Docker isn't available. The tarball is downloaded from `registry.npmjs.org` over HTTPS, extracted via `tarfile.extractall(filter="data")` with hard size and file-count caps, then analysed in-process. Package JavaScript is **never executed** — only parsed via tree-sitter.

## What "full behavioural analysis" means here

The npm scanner runs the same alignment pipeline as the Python behavioural analyzer:

1. **Parsing.** Each `.js / .mjs / .cjs / .jsx / .ts / .mts / .cts / .tsx` file is parsed with `tree-sitter-javascript` / `tree-sitter-typescript`.
2. **Tool discovery.** Calls of the form `<expr>.tool(...)`, `<expr>.registerTool(...)`, `<expr>.prompt(...)`, `<expr>.registerPrompt(...)`, `<expr>.resource(...)`, `<expr>.registerResource(...)` are detected — covering the MCP TypeScript SDK's high-level API regardless of how the operator names their server object.
3. **Context extraction.** For each registration the scanner builds the same `FunctionContext` the Python pipeline uses: imports, function calls, string literals, parameter names, JSDoc/`description`, heuristic booleans for file / network / subprocess / `eval` use, and so on.
4. **Alignment check.** The orchestrator (`AlignmentOrchestrator`) calls the configured LLM to compare the *declared* description against the *observed* behaviour and emits `SecurityFinding`s with the existing threat taxonomy.

The static dataflow / call-graph machinery used for Python (forward flow from parameters, cross-file taint) is **not** run on JS in this release. The LLM sees the same evidence shape, but the JS pipeline relies on lexical signals rather than full dataflow. This is enough to catch description-vs-behavior mismatches; deeper dataflow on JS will follow.

## Prerequisites

- **For Docker mode:** Docker installed and running.
- **For local mode:** Python 3.12+ (for the `tarfile` data filter). No Node.js / npm CLI required in either mode.
- **LLM API key** (`MCP_SCANNER_LLM_API_KEY`) for the alignment check itself.

## CLI Usage

### Latest version

```bash
mcp-scanner npm-scan @modelcontextprotocol/server-everything
```

### Specific version

```bash
mcp-scanner npm-scan my-mcp-server --version 1.2.3
```

### Local mode (no Docker, SDK/CI runners)

```bash
mcp-scanner npm-scan my-mcp-server --no-docker
```

### Save results to file

```bash
mcp-scanner npm-scan my-mcp-server -o results.json --format detailed
```

### Force rebuild the npm Docker image

```bash
mcp-scanner npm-scan my-mcp-server --rebuild-image
```

### All flags

```bash
mcp-scanner npm-scan <package> [--version VERSION] [--output FILE]
                               [--format {raw,summary,detailed,by_tool,by_analyzer,by_severity,table}]
                               [--verbose] [--raw] [--rebuild-image] [--no-docker]
                               [--severity-filter {all,high,medium,low,safe}]
                               [--tool-filter PATTERN] [--hide-safe] [--stats]
```

## SDK Usage

```python
from mcpscanner.core.npm_scanner import NPMPackageScanner

# Docker mode (recommended for untrusted packages).
scanner = NPMPackageScanner()
results = scanner.scan_package("@modelcontextprotocol/server-everything")
print(f"Safe: {results['is_safe']}, Findings: {results['total_findings']}")

# Local SDK mode — no Docker required. Package JS is never executed.
sdk = NPMPackageScanner(use_docker=False)
results = sdk.scan_package("my-mcp-server", version="1.2.3")

for finding in results["findings"]:
    print(f"[{finding['severity']}] {finding['summary']}")
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SCANNER_LLM_API_KEY` | (none) | API key for the LLM provider (required for alignment) |
| `MCP_SCANNER_LLM_MODEL` | `gpt-4o-mini` | LLM model to use |
| `MCP_SCANNER_LLM_BASE_URL` | (none) | Custom base URL for LLM API |
| `MCP_SCANNER_LLM_API_VERSION` | (none) | LLM API version (e.g. for Azure) |
| `MCP_SCANNER_NPM_DOCKER_IMAGE_NAME` | `mcp-scanner-npm` | Docker image name |
| `MCP_SCANNER_NPM_DOCKER_IMAGE_TAG` | `latest` | Docker image tag |
| `MCP_SCANNER_NPM_SCAN_TIMEOUT` | `300` | Container timeout in seconds |
| `MCP_SCANNER_NPM_REGISTRY_URL` | `https://registry.npmjs.org` | npm registry root (HTTPS only) |
| `MCP_SCANNER_PACKAGE_ARCHIVE_MAX_BYTES` | `52428800` (50 MB) | Local-mode max compressed archive size |
| `MCP_SCANNER_PACKAGE_EXTRACTED_MAX_BYTES` | `209715200` (200 MB) | Local-mode max extracted-tree size |
| `MCP_SCANNER_PACKAGE_EXTRACTED_MAX_FILES` | `10000` | Local-mode max number of members per tarball |
| `MCP_SCANNER_PACKAGE_DOWNLOAD_TIMEOUT` | `60` | Local-mode HTTP timeout in seconds |

## Security

### Docker mode (default)

- **No host volume mounts** — the package is downloaded and scanned inside the container; only JSON results return via stdout.
- **Non-root user** — the entrypoint drops to a dedicated UID (10001) inside the container.
- **Auto-removed** — `--rm` deletes the container after each scan.
- **Bridge networking** — the container has network access (needed for the npm registry and the LLM API) but uses Docker's default bridge, not host networking.

### Local (no-Docker) mode

- **No package execution.** Local mode parses sources via tree-sitter; the npm package's JavaScript is never run. No `npm install`, no `node`, no lifecycle scripts.
- **HTTPS-only registry.** The local path rejects non-TLS registry URLs.
- **Archive size cap** enforced both via the `Content-Length` header and a streaming byte counter.
- **Extraction caps** for total bytes and file count, applied before any byte hits the filesystem.
- **`tarfile.extractall(filter="data")`** (Python 3.12+) drops symlinks, hardlinks, absolute paths, traversal members, device files, and setuid/setgid bits.
- **Temp directory is private** to the scanner and cleaned up unconditionally on exit.

Docker remains the recommended sandbox for untrusted packages. Local mode is a smaller blast radius than `npm install`, but a weaker boundary than a container — choose it when Docker isn't available, not as your default.

## Output Format

```json
{
  "ecosystem": "npm",
  "package": "@modelcontextprotocol/server-everything",
  "version": "0.6.0",
  "source_dir": "/tmp/mcp-scanner-npm-…/src/package",
  "files_scanned": 12,
  "js_files_scanned": 12,
  "total_findings": 1,
  "behavioral_findings": 1,
  "is_safe": false,
  "scan_status": "completed",
  "findings": [
    {
      "analyzer": "behavioral",
      "severity": "HIGH",
      "threat_category": "DATA EXFILTRATION",
      "summary": "Line 14: DATA_EXFILTRATION - Description claims: 'Echo back text' | Actual behavior: reads /etc/passwd and POSTs it to evil.example.com",
      "details": {
        "function_name": "exfil",
        "decorator_type": "server.tool",
        "line_number": 14,
        "language": "javascript"
      }
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

| `error_code`                | Mapped Python exception | CLI exit code | Notes                                                                |
|-----------------------------|-------------------------|---------------|----------------------------------------------------------------------|
| `llm_not_configured`        | `LLMNotConfiguredError` | `2`           | `MCP_SCANNER_LLM_API_KEY` (or `LLM_API_KEY` inside Docker) unset.    |
| `package_download_failed`   | `NPMScanError`          | `1`           | HTTPS / host-allow-list / SRI integrity failure during tarball fetch.|
| `package_extraction_failed` | `NPMScanError`          | `1`           | Tarball failed traversal / size / file-count caps.                   |
| `scan_failed`               | `NPMScanError`          | `1`           | Catch-all (analyzer crash, unexpected internal error).               |

The contract is identical between Docker and SDK modes.

## Known Limitations

- Low-level handlers registered via `server.setRequestHandler(CallToolRequestSchema, …)` are not extracted per-tool — the scanner would have to follow conditional dispatch inside the handler. Refactor to the high-level SDK (`server.tool(...)`) for coverage.
- Vendored copies of dependencies (any `node_modules/` directory inside the tarball, plus `dist/`, `build/`, `out/`, `coverage/`) are skipped.
- Static dataflow / cross-file taint analysis is not yet implemented for JS in this release. The LLM relies on the same lexical evidence the Python pipeline collects, but without the precise per-parameter flows.
