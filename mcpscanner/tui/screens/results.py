from __future__ import annotations

import json
from typing import Any, Dict, List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Static,
)

from mcpscanner.tui.widgets.stats_bar import StatsBar


class ResultsScreen(Screen):
    BINDINGS = [
        Binding("escape", "new_scan", "New Scan", priority=True),
        Binding("e", "export", "Export", priority=True),
    ]

    def __init__(self, results_dict: dict) -> None:
        super().__init__()
        self.results_dict = results_dict
        self.scan_results: List[Dict[str, Any]] = results_dict.get("scan_results", [])

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="results-container"):
            with Horizontal(id="results-header"):
                server = self.results_dict.get(
                    "server_url", self.results_dict.get("mcp_server_repository", "")
                )
                yield Static(f"  Results: {server}", id="results-title")
                with Horizontal(id="results-actions"):
                    yield Button("Export", id="export-btn", classes="-secondary")
                    yield Button("New Scan", id="new-scan-btn", variant="success")

            yield StatsBar(self.scan_results)
            yield DataTable(id="results-table", cursor_type="row", zebra_stripes=True)
            yield Static("Select a row to view details.", id="detail-panel")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.add_columns("Status", "Name", "Severity", "Analyzer", "Threat")

        for result in self.scan_results:
            name = result.get(
                "tool_name",
                result.get("package_name", result.get("prompt_name", "Unknown")),
            )
            is_safe = result.get("is_safe", True)
            status = "[#3fb950]SAFE[/]" if is_safe else "[#f85149]UNSAFE[/]"

            findings = result.get("findings", {})
            severities = []
            analyzers_used = []
            threats = []

            for analyzer_key, data in findings.items():
                sev = data.get("severity", "SAFE")
                if sev != "SAFE":
                    severities.append(sev)
                short_name = analyzer_key.replace("_analyzer", "").upper()
                analyzers_used.append(short_name)
                for t in data.get("threat_names", []):
                    if t not in threats:
                        threats.append(t)

            highest = _highest_severity(severities) if severities else "SAFE"
            severity_display = _severity_styled(highest)
            analyzer_display = ", ".join(analyzers_used[:3]) if analyzers_used else "—"
            threat_display = ", ".join(threats[:2]) if threats else "—"

            table.add_row(status, name, severity_display, analyzer_display, threat_display)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row is not None and 0 <= event.cursor_row < len(self.scan_results):
            result = self.scan_results[event.cursor_row]
            self._show_detail(result)

    def _show_detail(self, result: Dict[str, Any]) -> None:
        name = result.get(
            "tool_name",
            result.get("package_name", result.get("prompt_name", "Unknown")),
        )
        desc = result.get(
            "tool_description",
            result.get("vulnerability_description", result.get("prompt_description", "")),
        )
        is_safe = result.get("is_safe", True)
        status_color = "#3fb950" if is_safe else "#f85149"
        status_text = "SAFE" if is_safe else "UNSAFE"

        lines = [f"[bold {status_color}]{status_text}[/]  [bold]{name}[/]"]

        if desc:
            truncated = desc[:300] + "..." if len(desc) > 300 else desc
            lines.append(f"[#8b949e]{truncated}[/]")

        for analyzer_key, data in result.get("findings", {}).items():
            sev = data.get("severity", "SAFE")
            sev_color = _severity_color(sev)
            label = analyzer_key.replace("_analyzer", "").upper()
            summary = data.get("threat_summary", "")
            threat_names = data.get("threat_names", [])

            parts = [f"[bold]Analyzer:[/] {label}  [{sev_color}]{sev}[/]"]
            if summary:
                parts.append(f"  {summary[:150]}")
            if threat_names:
                parts.append(f"  Threats: {', '.join(threat_names)}")
            lines.append("  ".join(parts))

        self.query_one("#detail-panel", Static).update("\n".join(lines))

    # ── Actions ─────────────────────────────────────────

    def action_new_scan(self) -> None:
        from mcpscanner.tui.screens.welcome import WelcomeScreen

        self.app.switch_screen(WelcomeScreen())

    def action_export(self) -> None:
        self.app.push_screen(ExportModal(self.results_dict))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "new-scan-btn":
            self.action_new_scan()
        elif event.button.id == "export-btn":
            self.action_export()


class ExportModal(Screen):
    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
    ]

    DEFAULT_CSS = """
    ExportModal {
        align: center middle;
    }
    """

    def __init__(self, results_dict: dict) -> None:
        super().__init__()
        self.results_dict = results_dict

    def compose(self) -> ComposeResult:
        with Vertical(id="export-dialog"):
            yield Static("[bold]Export Results[/]", id="export-title")
            yield Input(
                value="scan_results.json",
                placeholder="filename.json",
                id="export-filename",
            )
            with Horizontal(id="export-buttons"):
                yield Button("Cancel", id="export-cancel", classes="-secondary")
                yield Button("Save", id="export-save", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "export-cancel":
            self.dismiss()
        elif event.button.id == "export-save":
            filename = self.query_one("#export-filename", Input).value.strip()
            if not filename:
                self.notify("Please enter a filename", severity="error")
                return
            try:
                with open(filename, "w") as f:
                    json.dump(self.results_dict, f, indent=2, default=str)
                self.notify(f"Results saved to {filename}", title="Export")
                self.dismiss()
            except Exception as exc:
                self.notify(f"Export failed: {exc}", severity="error")

    def action_dismiss(self) -> None:
        self.dismiss()


def _highest_severity(severities: list[str]) -> str:
    order = {"HIGH": 0, "UNKNOWN": 0, "MEDIUM": 1, "LOW": 2, "SAFE": 3}
    return min(severities, key=lambda s: order.get(s, 3))


def _severity_styled(severity: str) -> str:
    colors = {
        "HIGH": "#f85149",
        "UNKNOWN": "#f85149",
        "MEDIUM": "#d29922",
        "LOW": "#e3b341",
        "SAFE": "#3fb950",
    }
    color = colors.get(severity, "#8b949e")
    return f"[bold {color}]{severity}[/]"


def _severity_color(severity: str) -> str:
    return {
        "HIGH": "#f85149",
        "UNKNOWN": "#f85149",
        "MEDIUM": "#d29922",
        "LOW": "#e3b341",
        "SAFE": "#3fb950",
    }.get(severity, "#8b949e")
