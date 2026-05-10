from pathlib import Path

from textual.app import App
from textual.binding import Binding

from mcpscanner.tui.screens.welcome import WelcomeScreen

CSS_PATH = Path(__file__).parent / "styles" / "app.tcss"


class MCPScannerApp(App):
    TITLE = "MCP Scanner"
    SUB_TITLE = "Security Analysis for MCP Servers"
    CSS_PATH = CSS_PATH

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("f1", "help", "Help"),
    ]

    def on_mount(self) -> None:
        self.push_screen(WelcomeScreen())

    def action_help(self) -> None:
        self.notify(
            "MCP Scanner TUI - Use arrow keys to navigate, Enter to select, Esc to go back.",
            title="Help",
            timeout=5,
        )


def main() -> None:
    app = MCPScannerApp()
    app.run()


if __name__ == "__main__":
    main()
