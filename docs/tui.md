# TUI (Terminal User Interface)

## Overview

The MCP Scanner TUI provides an interactive, menu-driven terminal interface for running security scans. Built with [Textual](https://textual.textualize.io/), it offers a guided experience across all scan modes without needing to remember CLI flags.

## Installation

The TUI is included with the MCP Scanner package. The `textual` dependency is installed automatically.

```bash
# If installed via uv
uv tool install cisco-ai-mcp-scanner

# For local development
uv sync
```

## Launch

```bash
# Via entry point
mcp-scanner-tui

# Via Python module
python -m mcpscanner.tui.app
```

## Screens

### 1. Welcome Screen

The entry screen displays the Cisco MCP Scanner branding and a list of scan modes. Select a mode using arrow keys and Enter, or press the corresponding number key:

| Key | Mode | Description |
|-----|------|-------------|
| `1` | Remote MCP Server | Scan a remote server via SSE or streamable HTTP |
| `2` | Stdio MCP Server | Launch and scan a local stdio server |
| `3` | Config File | Scan servers defined in an MCP config file |
| `4` | Known Configs | Scan well-known client configs (Cursor, Windsurf, Claude, VS Code) |
| `5` | Static/CI-CD | Scan pre-generated JSON files offline |
| `6` | Vulnerable Packages | Scan Python dependencies for known CVEs |
| `7` | Behavioral Analysis | Analyze MCP server source code for behavioral threats |

### 2. Scan Configuration Screen

Each scan mode presents a tailored form with relevant input fields:

- **Remote**: Server URL, bearer token, analyzer selection
- **Stdio**: Command, arguments, environment variables, analyzer selection
- **Config**: Config file path, bearer token, analyzer selection
- **Known Configs**: Bearer token, analyzer selection
- **Static/CI-CD**: Tools JSON path, prompts JSON path, resources JSON path, analyzer selection
- **Vulnerable Packages**: Requirements file or project path, vulnerability service (PyPI/OSV), fix mode toggle
- **Behavioral**: Source file or directory path

All forms include input validation before starting the scan.

### 3. Scanning Progress Screen

Displays real-time scan progress:

- **Progress bar** with percentage indicator
- **Step status** showing the current scan phase
- **Live log** with scrollable output of scan events
- **Cancel button** to abort the scan (changes to "Back" on error)

### 4. Results Screen

Presents scan findings in a compact layout:

- **Stats bar** showing total, safe, unsafe counts and severity breakdown (H/M/L)
- **DataTable** with columns: Status, Name, Severity, Analyzer, Threat
- **Detail panel** that updates when a row is selected, showing full finding details
- **Export** results to JSON via the `e` key or Export button
- **New Scan** returns to the welcome screen via `Escape` or the New Scan button

## Keyboard Shortcuts

| Key | Action | Context |
|-----|--------|---------|
| `q` | Quit application | Global |
| `F1` | Show help | Global |
| `Escape` | Go back / New scan | Config, Results |
| `e` | Export results to JSON | Results |
| `1`-`7` | Quick select scan mode | Welcome |

## Examples

### Scan a Remote MCP Server

1. Launch: `mcp-scanner-tui`
2. Press `1` (Remote MCP Server)
3. Enter URL: `https://mcp.deepwiki.com/mcp`
4. Check desired analyzers (YARA is selected by default)
5. Click **Start Scan**
6. View results in the DataTable

### Scan Static JSON Files (CI/CD)

1. Launch: `mcp-scanner-tui`
2. Press `5` (Static/CI-CD)
3. Enter tools JSON path: `/path/to/tools-list.json`
4. Click **Start Scan**
5. Export results with `e`

### Scan Vulnerable Packages

1. Launch: `mcp-scanner-tui`
2. Press `6` (Vulnerable Packages)
3. Enter path: `/path/to/requirements.txt`
4. Click **Start Scan**
5. Review vulnerabilities in the results table

## Theme

The TUI uses a dark theme inspired by the Cisco brand palette:

- **Primary**: `#049fd9` (Cisco blue)
- **Background**: `#0d1117` (dark)
- **Surface**: `#161b22`
- **Severity colors**: Red (`#f85149`) for HIGH, Yellow (`#d29922`) for MEDIUM, Amber (`#e3b341`) for LOW, Green (`#3fb950`) for SAFE

## Architecture

```
mcpscanner/tui/
├── __init__.py
├── app.py              # Main MCPScannerApp class and entry point
├── styles/
│   └── app.tcss        # Textual CSS theme and layout
├── screens/
│   ├── __init__.py
│   ├── welcome.py      # Welcome screen with mode selection
│   ├── scan_config.py  # Dynamic configuration forms
│   ├── scanning.py     # Progress screen with async worker
│   └── results.py      # Results DataTable and export modal
└── widgets/
    ├── __init__.py
    └── stats_bar.py    # Summary statistics bar
```

## Proxy Configuration

If you have a system HTTP proxy that interferes with localhost connections (common on macOS), bypass it with:

```bash
NO_PROXY="127.0.0.1,localhost" mcp-scanner-tui
```
