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
        table.add_columns("Tool Name", "Severity", "Analyzer", "Threat", "AITech ID - Name")
        yield table

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for result in self.results:
            name = result.get("tool_name", result.get("package_name", result.get("prompt_name", "Unknown")))

            findings = result.get("findings", {})
            severities = []
            analyzers_used = []
            threats = []
            aitech_entries: list[str] = []

            for analyzer_key, data in findings.items():
                sev = data.get("severity", "UNKNOWN")
                severities.append(sev)
                short_name = analyzer_key.replace("_analyzer", "").upper()
                analyzers_used.append(short_name)
                for t in data.get("threat_names", []):
                    if t not in threats:
                        threats.append(t)
                for entry in _extract_aitech(data):
                    if entry not in aitech_entries:
                        aitech_entries.append(entry)

            highest = _highest_severity(severities)
            severity_display = _severity_styled(highest)
            analyzer_display = ", ".join(analyzers_used[:3]) if analyzers_used else "—"
            threat_display = ", ".join(threats[:2]) if threats else "—"
            aitech_display = ", ".join(aitech_entries[:2]) if aitech_entries else "—"

            if len(name) > 30:
                name = name[:27] + "..."

            table.add_row(
                name, severity_display, analyzer_display, threat_display, aitech_display
            )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row is not None and 0 <= event.cursor_row < len(self.results):
            self.post_message(self.RowSelected(self.results[event.cursor_row]))


def _highest_severity(severities: list[str]) -> str:
    """Roll up a list of severities into the single highest one.

    Mirrors the model used by :func:`mcpscanner.core.result.get_highest_severity`:
    ``UNKNOWN`` represents "not yet analyzed / analyzer didn't run" and is
    *displaced* by any concrete severity (``HIGH``/``MEDIUM``/``LOW``/``INFO``/
    ``SAFE``). When only ``UNKNOWN`` entries are present (or the list is
    empty), the rollup is ``UNKNOWN``.
    """
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "SAFE": 4}
    concrete = [s for s in severities if s and s.upper() in order]
    if concrete:
        return min(concrete, key=lambda s: order[s.upper()]).upper()
    return "UNKNOWN"


def _severity_styled(severity: str) -> str:
    colors = {
        "HIGH": "#f85149",
        "UNKNOWN": "#a371f7",
        "MEDIUM": "#d29922",
        "LOW": "#e3b341",
        "SAFE": "#3fb950",
    }
    color = colors.get(severity, "#8b949e")
    return f"[bold {color}]{severity}[/]"


def _extract_aitech(analyzer_data: Dict[str, Any]) -> List[str]:
    """Return AITech identifiers/names from a finding's taxonomy data."""
    entries: List[str] = []
    taxonomies = analyzer_data.get("mcp_taxonomies")
    if not isinstance(taxonomies, list):
        taxonomies = []
        single = analyzer_data.get("mcp_taxonomy") or analyzer_data.get("threats")
        if isinstance(single, dict):
            taxonomies = [single]

    for tax in taxonomies:
        if not isinstance(tax, dict):
            continue
        aitech_id = tax.get("aitech")
        aitech_name = tax.get("aitech_name")
        if aitech_id and aitech_name:
            entries.append(f"{aitech_id} - {aitech_name}")
        elif aitech_id:
            entries.append(str(aitech_id))
        elif aitech_name:
            entries.append(str(aitech_name))
    return entries
