from __future__ import annotations

from typing import Any, Dict, List

from textual.app import ComposeResult
from textual.message import Message
from textual.widget import Widget
from textual.widgets import DataTable


class ResultsTable(Widget):
    DEFAULT_CSS = """
    ResultsTable {
        height: 1fr;
    }
    """

    class RowSelected(Message):
        def __init__(self, result: Dict[str, Any]) -> None:
            super().__init__()
            self.result = result

    def __init__(self, results: List[Dict[str, Any]]) -> None:
        super().__init__()
        self.results = results

    def compose(self) -> ComposeResult:
        table = DataTable(id="findings-table", cursor_type="row")
        table.add_columns("Status", "Name", "Severity", "Analyzer", "Threat")
        yield table

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for result in self.results:
            name = result.get("tool_name", result.get("package_name", result.get("prompt_name", "Unknown")))
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

            if len(name) > 30:
                name = name[:27] + "..."

            table.add_row(status, name, severity_display, analyzer_display, threat_display)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row is not None and 0 <= event.cursor_row < len(self.results):
            self.post_message(self.RowSelected(self.results[event.cursor_row]))


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
