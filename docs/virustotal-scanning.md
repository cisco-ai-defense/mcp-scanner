# VirusTotal Scanning

The VirusTotal analyzer scans files and directories against [VirusTotal's](https://www.virustotal.com/) malware database using SHA256 hash lookups. It is a standalone analyzer that can be invoked via the `virustotal` CLI subcommand or included in `--analyzers virustotal`.

## How It Works

1. **Hash Lookup** — Each file's SHA256 hash is computed locally and submitted to the VirusTotal API. No file content is uploaded by default.
2. **Extension Filtering** — Files are filtered using configurable inclusion/exclusion extension lists:
   - **Exclusion list** (checked first): known text/code extensions (`.py`, `.js`, `.md`, etc.) are skipped.
   - **Inclusion list**: known binary formats (`.exe`, `.dll`, `.pdf`, `.zip`, etc.) are scanned.
   - Files with unknown extensions are skipped.
3. **File Limit** — A configurable per-directory limit prevents excessive API usage (default: 10 files).
4. **Optional Upload** — If `MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES=true`, files not found in VirusTotal's database are uploaded for analysis.

## Configuration

### Required

```bash
# VirusTotal API key (get one free at https://www.virustotal.com/)
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

### Optional

```bash
# Explicitly disable VirusTotal scanning (default: auto-enabled when API key is set)
export MCP_SCANNER_VIRUSTOTAL_ENABLED=false

# Upload unknown files to VirusTotal for scanning (default: false)
export MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES=false

# Max files to scan per directory (default: 10, set to 0 for unlimited)
export MCP_SCANNER_VT_MAX_FILES=10
```

## CLI Usage

### Subcommand Mode

```bash
# Scan a single file
mcp-scanner virustotal /path/to/suspicious_file.exe

# Scan a directory
mcp-scanner virustotal /path/to/mcp_server_package/

# With detailed output
mcp-scanner virustotal /path/to/mcp_server_package/ --format detailed

# Table format
mcp-scanner virustotal /path/to/mcp_server_package/ --format table

# Save results to file
mcp-scanner virustotal /path/to/file.bin --output vt_results.json --format raw

# Verbose mode (shows debug logs)
mcp-scanner virustotal /path/to/file.bin -v
```

### As Part of Analyzers Flag

```bash
# Include VirusTotal alongside other analyzers
mcp-scanner --analyzers yara,virustotal --format summary
```

## SDK Usage

```python
from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer

# Create analyzer
vt = VirusTotalAnalyzer(
    api_key="your_api_key",
    enabled=True,
    upload_files=False,
    max_files=10,
)

# Scan a single file
finding = vt.analyze_file("/path/to/file.exe")
if finding:
    print(f"MALWARE DETECTED: {finding.summary}")

# Scan a directory
findings = vt.analyze_directory("/path/to/directory/")
for f in findings:
    print(f"{f.severity}: {f.summary}")

# Check scan summary after directory scan
summary = vt.last_scan_summary
print(f"Scanned: {summary['scanned']}, Malicious: {summary['malicious']}")
```

## Output Formats

### Summary Format

```
=== MCP Scanner Results Summary ===

Scan Target: virustotal:/path/to/dir
Total tools scanned: 1
Items matching filters: 1
Safe items: 0
Unsafe items: 1

=== Unsafe Items ===
1. malware.exe (tool) - HIGH (1 findings)
```

### Table Format

```
=== MCP Scanner Results Table ===

Scan Target                    File                           Status     VIRUSTOTAL      Severity
————————————————————————————————————————————————————————————————————————————————————————————————————
dir                            malware.exe                    UNSAFE     HIGH            🔴 HIGH
dir                            clean_file.pdf                 SAFE       SAFE            🟢 SAFE
```

## Rate Limits

VirusTotal free tier:
- **4 requests/minute**
- **500 requests/day**

The analyzer automatically handles rate limiting with configurable delays between requests. Use `MCP_SCANNER_VT_MAX_FILES` to control how many files are scanned per directory.

## Security & Privacy

- **Hash-only by default**: Only SHA256 hashes are sent to VirusTotal. File contents are never uploaded unless `MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES=true`.
- **Extension filtering**: Only known binary file types are scanned; source code and text files are skipped by default.
- **Configurable**: All behavior can be customized via environment variables.
