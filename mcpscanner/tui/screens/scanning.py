from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, ProgressBar, RichLog, Static
from textual.worker import Worker, WorkerState

logger = logging.getLogger(__name__)


class ScanningScreen(Screen):
    BINDINGS = [
        Binding("escape", "cancel_scan", "Cancel"),
    ]

    def __init__(self, scan_config: dict) -> None:
        super().__init__()
        self.scan_config = scan_config
        self._worker: Worker | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="scanning-container"):
            yield Static(
                f"  Scanning: {self._scan_label()}",
                id="scanning-title",
            )
            yield ProgressBar(total=100, show_eta=False, id="progress-bar")
            yield Static("", id="scan-steps")
            yield RichLog(highlight=True, markup=True, id="scan-log")
            yield Button("Cancel", id="cancel-btn", classes="-danger")
        yield Footer()

    def on_mount(self) -> None:
        self._worker = self.run_worker(
            self._run_scan(), exclusive=True, thread=False
        )

    def _scan_label(self) -> str:
        mode = self.scan_config.get("mode", "")
        if mode == "remote":
            return self.scan_config.get("server_url", "remote server")
        if mode == "stdio":
            return self.scan_config.get("stdio_command", "stdio server")
        if mode == "config":
            return self.scan_config.get("config_path", "config file")
        if mode == "known-configs":
            return "well-known configs"
        if mode == "static":
            return self.scan_config.get("tools_path", "static files")
        if mode == "vulnerable-package":
            return self.scan_config.get("scan_path", "packages")
        if mode == "behavioral":
            return self.scan_config.get("source_path", "source")
        if mode == "virustotal":
            return self.scan_config.get("vt_scan_path", "files")
        return mode

    def _log(self, message: str, style: str = "") -> None:
        log_widget = self.query_one("#scan-log", RichLog)
        if style:
            log_widget.write(f"[{style}]{message}[/]")
        else:
            log_widget.write(message)

    def _set_step(self, text: str) -> None:
        self.query_one("#scan-steps", Static).update(text)

    def _set_progress(self, value: int) -> None:
        self.query_one("#progress-bar", ProgressBar).update(progress=value)

    async def _run_scan(self) -> None:
        mode = self.scan_config["mode"]
        try:
            self._log(f"Starting {mode} scan...", "bold cyan")
            self._set_step("  Initializing scanner...")
            self._set_progress(10)

            results_dict = await self._execute_scan()

            self._set_progress(100)
            self._set_step("  [bold green]Scan complete![/]")
            self._log("Scan finished successfully.", "bold green")

            await asyncio.sleep(0.5)

            from mcpscanner.tui.screens.results import ResultsScreen

            self.app.switch_screen(ResultsScreen(results_dict))

        except asyncio.CancelledError:
            self._log("Scan cancelled.", "bold yellow")
            raise
        except Exception as exc:
            logger.exception("Scan failed")
            self._set_step(f"  [bold red]Error: {exc}[/]")
            self._log(f"Scan failed: {exc}", "bold red")
            self._log(
                "Press Escape to go back and try again.",
                "bold yellow",
            )
            self.notify(str(exc), severity="error", title="Scan Failed")

            cancel_btn = self.query_one("#cancel-btn", Button)
            cancel_btn.label = "Back"
            cancel_btn.remove_class("-danger")
            cancel_btn.add_class("-secondary")

    async def _execute_scan(self) -> dict:
        mode = self.scan_config["mode"]

        if mode == "vulnerable-package":
            return await self._scan_vulnerable_packages()
        if mode == "behavioral":
            return await self._scan_behavioral()
        if mode == "known-configs":
            return await self._scan_known_configs()
        if mode == "config":
            return await self._scan_config_file()
        if mode == "static":
            return await self._scan_static()
        if mode == "virustotal":
            return await self._scan_virustotal()

        return await self._scan_server()

    # ── Server scans (remote / stdio) ───────────────────

    async def _scan_server(self) -> dict:
        from mcpscanner.cli import _build_config
        from mcpscanner.core.auth import Auth
        from mcpscanner.core.models import AnalyzerEnum
        from mcpscanner.core.mcp_models import StdioServer
        from mcpscanner.core.report_generator import results_to_json
        from mcpscanner.core.scanner import Scanner

        analyzers = self._get_analyzers()
        config = _build_config(analyzers)
        scanner = Scanner(config)
        mode = self.scan_config["mode"]

        self._set_step("  Connecting to server...")
        self._set_progress(20)
        self._log("Connecting to MCP server...")

        auth = None
        token = self.scan_config.get("bearer_token")
        if token:
            auth = Auth.bearer(token)

        if mode == "remote":
            server_url = self.scan_config["server_url"]
            self._log(f"Scanning remote server: {server_url}")
            self._set_step("  Scanning tools...")
            self._set_progress(40)

            results = await scanner.scan_remote_server_tools(
                server_url, auth=auth, analyzers=analyzers
            )
            server_label = server_url

        elif mode == "stdio":
            cmd = self.scan_config["stdio_command"]
            args_str = self.scan_config.get("stdio_args", "")
            env_str = self.scan_config.get("stdio_env", "")

            args = [a.strip() for a in args_str.split(",") if a.strip()] if args_str else []
            env = {}
            if env_str:
                for pair in env_str.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        env[k.strip()] = v.strip()

            server_config = StdioServer(command=cmd, args=args, env=env or None)
            self._log(f"Scanning stdio server: {cmd}")
            self._set_step("  Scanning tools...")
            self._set_progress(40)

            results = await scanner.scan_stdio_server_tools(
                server_config, analyzers=analyzers
            )
            server_label = f"stdio:{cmd} {' '.join(args)}".strip()
        else:
            raise ValueError(f"Unsupported mode: {mode}")

        self._set_step("  Processing results...")
        self._set_progress(80)
        self._log(f"Found {len(results)} tools, processing results...")

        json_results = await results_to_json(results)

        return {
            "server_url": server_label,
            "scan_results": json_results,
            "requested_analyzers": [a.value for a in analyzers],
        }

    # ── Config scan ─────────────────────────────────────

    async def _scan_config_file(self) -> dict:
        from mcpscanner.cli import _build_config
        from mcpscanner.core.auth import Auth
        from mcpscanner.core.models import AnalyzerEnum
        from mcpscanner.core.report_generator import results_to_json
        from mcpscanner.core.scanner import Scanner

        analyzers = self._get_analyzers()
        config = _build_config(analyzers)
        scanner = Scanner(config)

        config_path = self.scan_config["config_path"]
        token = self.scan_config.get("bearer_token")
        auth = Auth.bearer(token) if token else None

        self._set_step("  Reading config file...")
        self._set_progress(20)
        self._log(f"Scanning config: {config_path}")

        self._set_step("  Scanning servers from config...")
        self._set_progress(40)

        results = await scanner.scan_mcp_config_file(
            config_path, analyzers=analyzers, auth=auth
        )

        self._set_step("  Processing results...")
        self._set_progress(80)

        json_results = await results_to_json(results)

        return {
            "server_url": config_path,
            "scan_results": json_results,
            "requested_analyzers": [a.value for a in analyzers],
        }

    # ── Known configs ───────────────────────────────────

    async def _scan_known_configs(self) -> dict:
        from mcpscanner.cli import _build_config
        from mcpscanner.core.auth import Auth
        from mcpscanner.core.models import AnalyzerEnum
        from mcpscanner.core.report_generator import results_to_json
        from mcpscanner.core.scanner import Scanner

        analyzers = self._get_analyzers()
        config = _build_config(analyzers)
        scanner = Scanner(config)

        token = self.scan_config.get("bearer_token")
        auth = Auth.bearer(token) if token else None

        self._set_step("  Discovering well-known configs...")
        self._set_progress(20)
        self._log("Scanning well-known MCP client configs...")

        self._set_step("  Scanning servers...")
        self._set_progress(40)

        results_by_config = await scanner.scan_well_known_mcp_configs(
            analyzers=analyzers, auth=auth
        )

        self._set_step("  Processing results...")
        self._set_progress(80)

        all_results = []
        for source, tool_results in results_by_config.items():
            json_results = await results_to_json(tool_results)
            for r in json_results:
                r["server_source"] = source
            all_results.extend(json_results)

        return {
            "server_url": "well-known-configs",
            "scan_results": all_results,
            "requested_analyzers": [a.value for a in analyzers],
        }

    # ── Static scan ─────────────────────────────────────

    async def _scan_static(self) -> dict:
        from mcpscanner.cli import _build_config
        from mcpscanner.core.analyzers import YaraAnalyzer
        from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer
        from mcpscanner.core.models import AnalyzerEnum
        from mcpscanner.core.report_generator import results_to_json
        from mcpscanner.core.result import ToolScanResult, PromptScanResult, ResourceScanResult

        analyzer_enums = self._get_analyzers()
        cfg = _build_config(analyzer_enums)

        inner_analyzers = []
        if AnalyzerEnum.YARA in analyzer_enums:
            inner_analyzers.append(YaraAnalyzer())
        if AnalyzerEnum.LLM in analyzer_enums and cfg.llm_provider_api_key:
            from mcpscanner.core.analyzers import LLMAnalyzer
            inner_analyzers.append(LLMAnalyzer(cfg))
        if AnalyzerEnum.API in analyzer_enums and cfg.api_key:
            from mcpscanner.core.analyzers import ApiAnalyzer
            inner_analyzers.append(ApiAnalyzer(cfg))

        if not inner_analyzers:
            inner_analyzers.append(YaraAnalyzer())

        static = StaticAnalyzer(analyzers=inner_analyzers, config=cfg)
        all_results = []

        tools_path = self.scan_config.get("tools_path", "")
        prompts_path = self.scan_config.get("prompts_path", "")
        resources_path = self.scan_config.get("resources_path", "")

        self._set_step("  Loading static files...")
        self._set_progress(20)

        if tools_path:
            self._log(f"Scanning tools: {tools_path}")
            self._set_step("  Analyzing tools...")
            self._set_progress(40)
            tools_results = await static.scan_tools_file(tools_path)
            for r in tools_results:
                all_results.append(ToolScanResult(
                    tool_name=r["tool_name"],
                    tool_description=r.get("tool_description", ""),
                    status=r["status"],
                    analyzers=r.get("analyzers", []),
                    findings=r["findings"],
                ))

        if prompts_path:
            self._log(f"Scanning prompts: {prompts_path}")
            self._set_step("  Analyzing prompts...")
            self._set_progress(60)
            prompts_results = await static.scan_prompts_file(prompts_path)
            for r in prompts_results:
                all_results.append(PromptScanResult(
                    prompt_name=r["prompt_name"],
                    prompt_description=r.get("prompt_description", ""),
                    status=r["status"],
                    analyzers=r.get("analyzers", []),
                    findings=r["findings"],
                ))

        if resources_path:
            self._log(f"Scanning resources: {resources_path}")
            self._set_step("  Analyzing resources...")
            self._set_progress(70)
            resources_results = await static.scan_resources_file(resources_path)
            for r in resources_results:
                all_results.append(ResourceScanResult(
                    resource_uri=r["resource_uri"],
                    resource_name=r["resource_name"],
                    resource_mime_type=r.get("resource_mime_type", "unknown"),
                    status=r["status"],
                    analyzers=r.get("analyzers", []),
                    findings=r["findings"],
                ))

        self._set_step("  Processing results...")
        self._set_progress(80)

        json_results = await results_to_json(all_results)

        return {
            "server_url": tools_path or prompts_path or resources_path,
            "scan_results": json_results,
            "requested_analyzers": [a.value for a in analyzer_enums],
        }

    # ── Vulnerable packages ─────────────────────────────

    async def _scan_vulnerable_packages(self) -> dict:
        from mcpscanner.core.analyzers.vulnerable_package_analyzer import (
            VulnerablePackageAnalyzer,
        )
        from mcpscanner.core.models import AnalyzerEnum

        scan_path = self.scan_config["scan_path"]
        service = self.scan_config.get("vuln_service", "pypi")
        fix = self.scan_config.get("fix_mode", False)

        self._set_step("  Initializing pip-audit...")
        self._set_progress(20)
        self._log(f"Scanning: {scan_path} (service: {service})")

        analyzer = VulnerablePackageAnalyzer(
            enabled=True,
            vulnerability_service=service,
            fix_mode=fix,
        )

        self._set_step("  Running vulnerability scan...")
        self._set_progress(40)

        findings = analyzer.analyze_path(scan_path)

        self._set_step("  Processing results...")
        self._set_progress(80)
        self._log(f"Found {len(findings)} vulnerabilities")

        results = []
        vuln_map: dict[str, list] = {}
        for f in findings:
            pkg_key = f"{f.details.get('package_name', 'unknown')}=={f.details.get('installed_version', '?')}"
            vuln_map.setdefault(pkg_key, []).append(f)

        for pkg_key, pkg_findings in vuln_map.items():
            for finding in pkg_findings:
                vuln_id = finding.details.get("vulnerability_id", "")
                aliases = finding.details.get("aliases", [])
                desc = finding.details.get("description", "")

                tool_desc_parts = [f"{vuln_id}: {pkg_key}"]
                alias_str = ", ".join(aliases) if aliases else ""
                if alias_str:
                    tool_desc_parts.append(f"Aliases: {alias_str}")
                if desc:
                    tool_desc_parts.append(desc)

                analyzer_finding = {
                    "severity": finding.severity,
                    "threat_summary": finding.summary,
                    "threat_names": [finding.threat_category],
                    "total_findings": 1,
                    "mcp_taxonomies": (
                        [finding.mcp_taxonomy] if finding.mcp_taxonomy else []
                    ),
                }

                results.append({
                    "package_name": pkg_key,
                    "vulnerability_description": " | ".join(tool_desc_parts),
                    "status": "completed",
                    "is_safe": False,
                    "findings": {"vulnerable_package_analyzer": analyzer_finding},
                })

        if not results:
            results.append({
                "package_name": scan_path,
                "vulnerability_description": f"No vulnerabilities found in {os.path.basename(scan_path)}",
                "status": "completed",
                "is_safe": True,
                "findings": {
                    "vulnerable_package_analyzer": {
                        "severity": "SAFE",
                        "threat_summary": "No known vulnerabilities found",
                        "threat_names": [],
                        "total_findings": 0,
                        "mcp_taxonomies": [],
                    }
                },
            })

        return {
            "mcp_server_repository": f"vulnerable-package:{scan_path}",
            "scan_results": results,
            "requested_analyzers": ["vulnerable_package"],
        }

    # ── Behavioral ──────────────────────────────────────

    async def _scan_behavioral(self) -> dict:
        from mcpscanner.cli import _run_behavioral_analyzer_on_source

        source_path = self.scan_config["source_path"]

        self._set_step("  Analyzing source code...")
        self._set_progress(30)
        self._log(f"Behavioral analysis: {source_path}")

        self._set_step("  Running behavioral analyzer...")
        self._set_progress(50)

        results = await _run_behavioral_analyzer_on_source(source_path)

        self._set_step("  Processing results...")
        self._set_progress(80)

        return {
            "server_url": f"behavioral:{source_path}",
            "scan_results": results,
            "requested_analyzers": ["behavioral"],
        }

    # ── VirusTotal scan ──────────────────────────────────

    async def _scan_virustotal(self) -> dict:
        import os
        from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer
        from mcpscanner.config.constants import MCPScannerConstants as CONSTANTS

        scan_path = self.scan_config["vt_scan_path"]
        vt_upload = self.scan_config.get("vt_upload", False)

        vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not vt_api_key:
            raise ValueError(
                "VIRUSTOTAL_API_KEY environment variable is not set. "
                "Get a free key at https://www.virustotal.com/"
            )

        self._set_step("  Initializing VirusTotal analyzer...")
        self._set_progress(20)
        self._log(f"Scanning: {scan_path}")

        analyzer = VirusTotalAnalyzer(
            api_key=vt_api_key,
            enabled=True,
            upload_files=vt_upload,
            max_files=CONSTANTS.VIRUSTOTAL_MAX_FILES,
            inclusion_extensions=CONSTANTS.VIRUSTOTAL_INCLUSION_EXTENSIONS,
            exclusion_extensions=CONSTANTS.VIRUSTOTAL_EXCLUSION_EXTENSIONS,
        )

        self._set_step("  Scanning files with VirusTotal...")
        self._set_progress(40)

        if os.path.isfile(scan_path):
            finding = analyzer.analyze_file(scan_path)
            findings = [finding] if finding else []
            self._log(f"Scanned file: {os.path.basename(scan_path)}")
        elif os.path.isdir(scan_path):
            findings = analyzer.analyze_directory(scan_path)
            self._log(f"Scanned directory: {scan_path}")
        else:
            raise FileNotFoundError(f"Path does not exist: {scan_path}")

        self._set_step("  Processing results...")
        self._set_progress(80)

        results = []
        if findings:
            for finding in findings:
                file_path = (
                    finding.details.get("file_path", scan_path)
                    if finding.details else scan_path
                )
                analyzer_finding = {
                    "severity": finding.severity,
                    "threat_summary": finding.summary,
                    "threat_names": [finding.threat_category],
                    "total_findings": 1,
                    "mcp_taxonomies": [],
                }
                if finding.details:
                    taxonomy = {}
                    for key in ("aitech", "aitech_name", "aisubtech", "aisubtech_name", "taxonomy_description"):
                        if key in finding.details:
                            taxonomy[key.replace("taxonomy_description", "description")] = finding.details[key]
                    if taxonomy:
                        analyzer_finding["mcp_taxonomies"].append(taxonomy)

                results.append({
                    "tool_name": os.path.basename(file_path),
                    "tool_description": f"VirusTotal scan of {os.path.basename(file_path)}",
                    "status": "completed",
                    "is_safe": False,
                    "findings": {"virustotal_analyzer": analyzer_finding},
                })
                self._log(f"  MALWARE: {os.path.basename(file_path)} - {finding.summary}", "bold red")
        else:
            results.append({
                "tool_name": os.path.basename(scan_path),
                "tool_description": f"VirusTotal scan of {os.path.basename(scan_path)}",
                "status": "completed",
                "is_safe": True,
                "findings": {
                    "virustotal_analyzer": {
                        "severity": "SAFE",
                        "threat_summary": "No threats detected",
                        "threat_names": [],
                        "total_findings": 0,
                        "mcp_taxonomies": [],
                    }
                },
            })
            self._log("No threats detected.", "bold green")

        return {
            "server_url": f"virustotal:{scan_path}",
            "scan_results": results,
            "requested_analyzers": ["virustotal"],
        }

    # ── Helpers ──────────────────────────────────────────

    def _get_analyzers(self) -> list:
        from mcpscanner.core.models import AnalyzerEnum

        mapping = {
            "yara": AnalyzerEnum.YARA,
            "api": AnalyzerEnum.API,
            "llm": AnalyzerEnum.LLM,
        }
        selected = self.scan_config.get("analyzers", ["yara"])
        return [mapping[a] for a in selected if a in mapping]

    # ── Actions ─────────────────────────────────────────

    def action_cancel_scan(self) -> None:
        if self._worker and self._worker.state == WorkerState.RUNNING:
            self._worker.cancel()
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.action_cancel_scan()
