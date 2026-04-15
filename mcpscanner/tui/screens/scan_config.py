from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll, Horizontal
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
)

MODE_TITLES = {
    "remote": "Remote Server Scan",
    "stdio": "Stdio Server Scan",
    "config": "Config File Scan",
    "known-configs": "Well-Known Configs Scan",
    "static": "Static File Scan",
    "vulnerable-package": "Vulnerable Package Scan",
    "behavioral": "Behavioral Analysis",
    "virustotal": "VirusTotal Malware Scan",
}


class ScanConfigScreen(Screen):
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]

    def __init__(self, mode: str) -> None:
        super().__init__()
        self.mode = mode

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="config-container"):
            yield Static(
                f"  {MODE_TITLES.get(self.mode, self.mode)}",
                id="config-title",
            )
            yield from self._build_form()
            with Horizontal(id="config-buttons"):
                yield Button("Start Scan", id="start-scan-btn", variant="success")
                yield Button("Back", id="back-btn", classes="-secondary")
        yield Footer()

    def _build_form(self) -> ComposeResult:
        if self.mode == "remote":
            yield from self._remote_form()
        elif self.mode == "stdio":
            yield from self._stdio_form()
        elif self.mode == "config":
            yield from self._config_form()
        elif self.mode == "known-configs":
            yield from self._known_configs_form()
        elif self.mode == "static":
            yield from self._static_form()
        elif self.mode == "vulnerable-package":
            yield from self._vuln_packages_form()
        elif self.mode == "behavioral":
            yield from self._behavioral_form()
        elif self.mode == "virustotal":
            yield from self._virustotal_form()

    # ── Remote ──────────────────────────────────────────

    def _remote_form(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Server URL", classes="form-label")
            yield Input(
                placeholder="https://mcp-server.example.com/mcp",
                id="server-url",
            )
        with Vertical(classes="form-group"):
            yield Label("Bearer Token (optional)", classes="form-label")
            yield Input(placeholder="token...", id="bearer-token", password=True)
        yield from self._analyzer_checkboxes()
        yield from self._severity_select()

    # ── Stdio ───────────────────────────────────────────

    def _stdio_form(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Command", classes="form-label")
            yield Input(placeholder="npx -y @modelcontextprotocol/server-everything", id="stdio-command")
        with Vertical(classes="form-group"):
            yield Label("Arguments (comma-separated)", classes="form-label")
            yield Input(placeholder="--arg1,--arg2", id="stdio-args")
        with Vertical(classes="form-group"):
            yield Label("Environment Variables (KEY=VALUE, comma-separated)", classes="form-label")
            yield Input(placeholder="API_KEY=xxx,DEBUG=1", id="stdio-env")
        yield from self._analyzer_checkboxes()
        yield from self._severity_select()

    # ── Config ──────────────────────────────────────────

    def _config_form(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Config File Path", classes="form-label")
            yield Input(placeholder="/path/to/mcp-config.json", id="config-path")
        with Vertical(classes="form-group"):
            yield Label("Bearer Token (optional)", classes="form-label")
            yield Input(placeholder="token...", id="bearer-token", password=True)
        yield from self._analyzer_checkboxes()
        yield from self._severity_select()

    # ── Known configs ───────────────────────────────────

    def _known_configs_form(self) -> ComposeResult:
        yield Static(
            "  Scans well-known MCP client configurations:\n"
            "  Claude Desktop, Cursor, Windsurf, and others.\n\n"
            "  No additional configuration needed.",
            classes="form-group",
        )
        with Vertical(classes="form-group"):
            yield Label("Bearer Token (optional)", classes="form-label")
            yield Input(placeholder="token...", id="bearer-token", password=True)
        yield from self._analyzer_checkboxes()
        yield from self._severity_select()

    # ── Static ──────────────────────────────────────────

    def _static_form(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Tools JSON File", classes="form-label")
            yield Input(placeholder="/path/to/tools.json", id="tools-path")
        with Vertical(classes="form-group"):
            yield Label("Prompts JSON File (optional)", classes="form-label")
            yield Input(placeholder="/path/to/prompts.json", id="prompts-path")
        with Vertical(classes="form-group"):
            yield Label("Resources JSON File (optional)", classes="form-label")
            yield Input(placeholder="/path/to/resources.json", id="resources-path")
        yield from self._analyzer_checkboxes()
        yield from self._severity_select()

    # ── Vulnerable packages ─────────────────────────────

    def _vuln_packages_form(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Scan Path (requirements.txt, project dir, or .in file)", classes="form-label")
            yield Input(placeholder="/path/to/requirements.txt", id="scan-path")
        with Vertical(classes="form-group"):
            yield Label("Vulnerability Service", classes="form-label")
            yield Select(
                [("PyPI", "pypi"), ("OSV", "osv")],
                value="pypi",
                id="vuln-service",
            )
        with Vertical(classes="form-group"):
            yield Checkbox("Auto-fix vulnerable packages", id="fix-mode")

    # ── Behavioral ──────────────────────────────────────

    def _behavioral_form(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Source Path (Python file or directory)", classes="form-label")
            yield Input(placeholder="/path/to/mcp_server.py", id="source-path")
        yield from self._severity_select()

    # ── VirusTotal ─────────────────────────────────────

    def _virustotal_form(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Scan Path (file or directory)", classes="form-label")
            yield Input(placeholder="/path/to/file_or_directory", id="vt-scan-path")
        with Vertical(classes="form-group"):
            yield Checkbox("Upload unknown files to VirusTotal", id="vt-upload")

    # ── Shared widgets ──────────────────────────────────

    def _analyzer_checkboxes(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Analyzers", classes="form-label")
            with Horizontal(id="analyzer-checkboxes"):
                yield Checkbox("YARA", value=True, id="chk-yara")
                yield Checkbox("API", value=True, id="chk-api")
                yield Checkbox("LLM", value=False, id="chk-llm")

    def _severity_select(self) -> ComposeResult:
        with Vertical(classes="form-group"):
            yield Label("Severity Filter", classes="form-label")
            yield Select(
                [
                    ("All", "all"),
                    ("High", "high"),
                    ("Medium", "medium"),
                    ("Low", "low"),
                    ("Safe", "safe"),
                ],
                value="all",
                id="severity-filter",
            )

    # ── Actions ─────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "start-scan-btn":
            self._start_scan()

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def _gather_config(self) -> dict:
        config = {"mode": self.mode}

        def _val(widget_id: str) -> str:
            try:
                widget = self.query_one(f"#{widget_id}", Input)
                return widget.value.strip()
            except Exception:
                return ""

        def _checked(widget_id: str) -> bool:
            try:
                widget = self.query_one(f"#{widget_id}", Checkbox)
                return widget.value
            except Exception:
                return False

        def _select_val(widget_id: str) -> str:
            try:
                widget = self.query_one(f"#{widget_id}", Select)
                return str(widget.value) if widget.value is not Select.BLANK else ""
            except Exception:
                return ""

        if self.mode == "remote":
            config["server_url"] = _val("server-url")
            config["bearer_token"] = _val("bearer-token")
        elif self.mode == "stdio":
            config["stdio_command"] = _val("stdio-command")
            config["stdio_args"] = _val("stdio-args")
            config["stdio_env"] = _val("stdio-env")
        elif self.mode == "config":
            config["config_path"] = _val("config-path")
            config["bearer_token"] = _val("bearer-token")
        elif self.mode == "known-configs":
            config["bearer_token"] = _val("bearer-token")
        elif self.mode == "static":
            config["tools_path"] = _val("tools-path")
            config["prompts_path"] = _val("prompts-path")
            config["resources_path"] = _val("resources-path")
        elif self.mode == "vulnerable-package":
            config["scan_path"] = _val("scan-path")
            config["vuln_service"] = _select_val("vuln-service")
            config["fix_mode"] = _checked("fix-mode")
        elif self.mode == "behavioral":
            config["source_path"] = _val("source-path")
        elif self.mode == "virustotal":
            config["vt_scan_path"] = _val("vt-scan-path")
            config["vt_upload"] = _checked("vt-upload")

        analyzers = []
        if _checked("chk-yara"):
            analyzers.append("yara")
        if _checked("chk-api"):
            analyzers.append("api")
        if _checked("chk-llm"):
            analyzers.append("llm")
        config["analyzers"] = analyzers
        config["severity_filter"] = _select_val("severity-filter") or "all"

        return config

    def _validate(self, config: dict) -> str | None:
        mode = config["mode"]
        if mode == "remote" and not config.get("server_url"):
            return "Server URL is required"
        if mode == "stdio" and not config.get("stdio_command"):
            return "Stdio command is required"
        if mode == "config" and not config.get("config_path"):
            return "Config file path is required"
        if mode == "static" and not config.get("tools_path"):
            return "At least a tools JSON file is required"
        if mode == "vulnerable-package" and not config.get("scan_path"):
            return "Scan path is required"
        if mode == "behavioral" and not config.get("source_path"):
            return "Source path is required"
        if mode == "virustotal" and not config.get("vt_scan_path"):
            return "File or directory path is required"
        return None

    def _start_scan(self) -> None:
        config = self._gather_config()
        error = self._validate(config)
        if error:
            self.notify(error, severity="error", title="Validation Error")
            return

        from mcpscanner.tui.screens.scanning import ScanningScreen

        self.app.push_screen(ScanningScreen(config))
