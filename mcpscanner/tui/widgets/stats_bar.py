from __future__ import annotations

from typing import Any, Dict, List

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static


class StatsBar(Widget):
    DEFAULT_CSS = """
    StatsBar {
        height: auto;
        layout: horizontal;
        width: 100%;
        padding: 0 1;
        background: #161b22;
        border: solid #30363d;
        margin-bottom: 1;
    }
    """

    def __init__(self, results: List[Dict[str, Any]]) -> None:
        super().__init__()
        self.results = results

    def compose(self) -> ComposeResult:
        total = len(self.results)
        safe = sum(1 for r in self.results if r.get("is_safe", True))
        unsafe = total - safe

        severity_counts: dict[str, int] = {}
        for r in self.results:
            for analyzer_data in r.get("findings", {}).values():
                sev = analyzer_data.get("severity", "SAFE")
                if sev != "SAFE":
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

        high = severity_counts.get("HIGH", 0) + severity_counts.get("UNKNOWN", 0)
        medium = severity_counts.get("MEDIUM", 0)
        low = severity_counts.get("LOW", 0)

        line = (
            f"[bold]Total:[/] {total}  "
            f"[bold #3fb950]Safe:[/] {safe}  "
            f"[bold #f85149]Unsafe:[/] {unsafe}  "
            f"│  "
            f"[bold #f85149]H:[/] {high}  "
            f"[bold #d29922]M:[/] {medium}  "
            f"[bold #e3b341]L:[/] {low}"
        )
        yield Static(line)
