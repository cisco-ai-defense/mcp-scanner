from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, OptionList, Static
from textual.widgets._option_list import Option


SCAN_MODES = [
    ("remote", "Remote Server Scan", "SSE / streamable HTTP"),
    ("stdio", "Stdio Server Scan", "Local stdio transport"),
    ("config", "Config File Scan", "From MCP config file"),
    ("known-configs", "Well-Known Configs", "Claude, Cursor, Windsurf"),
    ("static", "Static File Scan", "Pre-generated JSON files"),
    ("vulnerable-packages", "Vulnerable Packages", "Python CVE scan"),
    ("behavioral", "Behavioral Analysis", "Docstring mismatch scan"),
]

LOGO = "[bold #049fd9]Cisco MCP Scanner[/]"


class WelcomeScreen(Screen):
    BINDINGS = [
        Binding("1", "select_mode(0)", "Remote", show=False),
        Binding("2", "select_mode(1)", "Stdio", show=False),
        Binding("3", "select_mode(2)", "Config", show=False),
        Binding("4", "select_mode(3)", "Known", show=False),
        Binding("5", "select_mode(4)", "Static", show=False),
        Binding("6", "select_mode(5)", "VulnPkg", show=False),
        Binding("7", "select_mode(6)", "Behavioral", show=False),
        Binding("escape", "app.quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="welcome-container"):
            yield Static(LOGO, id="welcome-title", markup=True)
            yield Static(
                "Comprehensive security analysis for MCP servers",
                id="welcome-subtitle",
            )
            with Vertical(id="mode-list-container"):
                option_list = OptionList(id="scan-mode-list")
                for i, (mode_id, label, desc) in enumerate(SCAN_MODES):
                    option_list.add_option(
                        Option(f"[{i + 1}]  {label}  [#6e7681]({desc})[/]", id=mode_id)
                    )
                    if i == 3:
                        option_list.add_option(None)
                yield option_list
            yield Static(
                "Press [bold]1-7[/] or [bold]Enter[/] to select  ·  [bold]Q[/] to quit",
                id="welcome-footer-text",
            )
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self._launch_mode(event.option.id)

    def action_select_mode(self, index: int) -> None:
        if 0 <= index < len(SCAN_MODES):
            self._launch_mode(SCAN_MODES[index][0])

    def _launch_mode(self, mode_id: str) -> None:
        from mcpscanner.tui.screens.scan_config import ScanConfigScreen

        self.app.push_screen(ScanConfigScreen(mode_id))
