from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Static


class FindingDetail(Widget):
    DEFAULT_CSS = """
    FindingDetail {
        height: auto;
        max-height: 18;
        padding: 1 2;
        background: #161b22;
        border: solid #30363d;
        margin-top: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._content = Static("Select a finding to view details.", id="detail-content")

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield self._content

    def update_finding(self, result: Dict[str, Any]) -> None:
        name = result.get("tool_name", result.get("package_name", result.get("prompt_name", "Unknown")))
        desc = result.get(
            "tool_description",
            result.get("vulnerability_description", result.get("prompt_description", "")),
        )
        is_safe = result.get("is_safe", True)

        lines = []
        status_color = "#3fb950" if is_safe else "#f85149"
        status_text = "SAFE" if is_safe else "UNSAFE"
        lines.append(f"[bold {status_color}]{status_text}[/]  [bold]{name}[/]")
        lines.append("")

        if desc:
            truncated = desc[:300] + "..." if len(desc) > 300 else desc
            lines.append(f"[#8b949e]{truncated}[/]")
            lines.append("")

        findings = result.get("findings", {})
        for analyzer_key, data in findings.items():
            severity = data.get("severity", "SAFE")
            sev_color = _severity_color(severity)
            analyzer_label = analyzer_key.replace("_analyzer", "").upper()
            lines.append(f"[bold]Analyzer:[/] {analyzer_label}  [{sev_color}]{severity}[/]")

            summary = data.get("threat_summary", "")
            if summary:
                trunc_summary = summary[:200] + "..." if len(summary) > 200 else summary
                lines.append(f"[bold]Summary:[/] {trunc_summary}")

            threat_names = data.get("threat_names", [])
            if threat_names:
                lines.append(f"[bold]Threats:[/] {', '.join(threat_names)}")

            taxonomies = data.get("mcp_taxonomies", [])
            for tax in taxonomies:
                aitech = tax.get("aitech", "")
                aitech_name = tax.get("aitech_name", "")
                aisubtech = tax.get("aisubtech", "")
                aisubtech_name = tax.get("aisubtech_name", "")
                lines.append("")
                lines.append(f"  [#39c5cf]Taxonomy:[/] {aitech} {aitech_name}")
                lines.append(f"  [#39c5cf]Sub-tech:[/] {aisubtech} {aisubtech_name}")
                tax_desc = tax.get("description", "")
                if tax_desc:
                    trunc_tax = tax_desc[:200] + "..." if len(tax_desc) > 200 else tax_desc
                    lines.append(f"  [#8b949e]{trunc_tax}[/]")

            lines.append("")

        self._content.update("\n".join(lines))


def _severity_color(severity: str) -> str:
    return {
        "HIGH": "#f85149",
        "UNKNOWN": "#f85149",
        "MEDIUM": "#d29922",
        "LOW": "#e3b341",
        "SAFE": "#3fb950",
    }.get(severity, "#8b949e")
