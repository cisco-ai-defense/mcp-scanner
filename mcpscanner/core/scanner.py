# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Scanner module for MCP Scanner SDK.

This module contains the unified scanner class that combines API and YARA analyzers.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
)

# MCP client imports
from mcp.client.session import ClientSession
from mcp.types import Tool as MCPTool, Prompt as MCPPrompt

try:
    from mcp.shared.exceptions import McpError
except (
    ImportError
):  # pragma: no cover - fallback for environments without mcp installed

    class McpError(Exception):
        """Fallback error class when MCP dependency is unavailable."""

        pass


from ..config.config import Config
from ..utils.logging_config import get_logger
from .analyzers.api_analyzer import ApiAnalyzer
from .analyzers.base import BaseAnalyzer, reportable_findings
from .analyzers.llm_analyzer import LLMAnalyzer
from .analyzers.meta_analyzer import MetaAnalyzer
from .analyzers.yara_analyzer import YaraAnalyzer
from .analyzers.behavioral import BehavioralCodeAnalyzer
from .analyzers.virustotal_analyzer import VirusTotalAnalyzer
from .analyzers.prompt_defense_analyzer import PromptDefenseAnalyzer
from .analyzers.readiness import ReadinessAnalyzer
from .auth import Auth
from .models import AnalyzerEnum
from .mcp_models import StdioServer, RemoteServer
from . import session as session_transport
from .resource_scan import (
    DEFAULT_ALLOWED_MIME_TYPES,
    extract_resource_text,
    mime_type_allowed,
    resource_placeholder,
)
from .orchestration import (
    AnalyzerBundle,
    analyze_instructions,
    analyze_prompt,
    analyze_resource,
    analyze_tool,
)
from .meta_runner import (
    DEFAULT_DESCRIPTION_BUDGET,
    DEFAULT_META_CONCURRENCY,
    INSTRUCTIONS_SPEC,
    PROMPT_SPEC,
    RESOURCE_SPEC,
    TOOL_SPEC,
    MetaAnalysisRunner,
    build_instructions_description,
    build_resource_description,
)
from ..config.config_parser import MCPConfigScanner
from .result import (
    ScanResult,
    ToolScanResult,
    PromptScanResult,
    ResourceScanResult,
    InstructionsScanResult,
)

ScannerFactory = Callable[[List[AnalyzerEnum], Optional[str]], "Scanner"]

logger = get_logger(__name__)


class Scanner:
    """Unified scanner class that combines API and YARA analyzers.

    This class provides a comprehensive scanning solution by combining
    API-based analysis and YARA pattern matching. It can connect to MCP servers
    to scan tools directly.

    Example:
        >>> from mcpscanner import Config, Scanner
        >>> config = Config(api_key="your_api_key", endpoint_url="https://eu.api.inspect.aidefense.security.cisco.com/api/v1")
        >>> scanner = Scanner(config)
        >>> # Scan a specific tool on a remote server
        >>> result = await scanner.scan_remote_server_tool("https://mcp-server.example.com", "tool_name")
        >>> # Or scan all tools on a remote server
        >>> results = await scanner.scan_remote_server_tools("https://mcp-server.example.com")
        >>> # You can also analyze content directly without connecting to a server
        >>> result = await scanner.analyze(name="tool_name", description="tool description")
    """

    DEFAULT_ANALYZERS = [AnalyzerEnum.API, AnalyzerEnum.YARA]

    def __init__(
        self,
        config: Config,
        rules_dir: Optional[str] = None,
        custom_analyzers: Optional[List[BaseAnalyzer]] = None,
    ):
        """Initialize a new Scanner instance.

        Args:
            config (Config): The configuration for the scanner.
            rules_dir (Optional[str]): Custom path to YARA rules directory.
            custom_analyzers (Optional[List[BaseAnalyzer]]): A list of custom analyzer instances.
        """
        self._config = config
        self._api_analyzer = ApiAnalyzer(config) if config.api_key else None
        self._yara_analyzer = YaraAnalyzer(rules_dir=rules_dir)

        # LLM analyzer can be used with either API key or Bedrock (AWS credentials).
        # Behavioral analyzer follows the same gate now that AlignmentLLMClient
        # supports Bedrock auth via bearer token / AWS provider chain.
        is_bedrock = config.llm_model and "bedrock/" in config.llm_model
        self._llm_analyzer = (
            LLMAnalyzer(config) if (config.llm_provider_api_key or is_bedrock) else None
        )
        self._behavioral_analyzer = (
            BehavioralCodeAnalyzer(config)
            if (config.llm_provider_api_key or is_bedrock)
            else None
        )
        self._behavioral_source_path = config.behavioral_source_path
        self._vt_analyzer = (
            VirusTotalAnalyzer(
                api_key=config.virustotal_api_key,
                enabled=config.virustotal_enabled,
                upload_files=config.virustotal_upload_files,
                max_files=config.virustotal_max_files,
                inclusion_extensions=config.virustotal_inclusion_extensions,
                exclusion_extensions=config.virustotal_exclusion_extensions,
            )
            if config.virustotal_enabled
            else None
        )
        # Readiness analyzer always available (no API keys needed)
        self._readiness_analyzer = ReadinessAnalyzer()
        # Prompt defense analyzer always available (pure regex, no API keys needed)
        self._prompt_defense_analyzer = PromptDefenseAnalyzer()
        # P1-3 fix: construct MetaAnalyzer once at __init__ under the same gate
        # used by LLM/Behavioral. The previous lazy-init path
        # (_validate_analyzer_requirements) was a method named "validate" that
        # silently mutated state, AND raced under FastAPI's shared-Scanner
        # dependency model — two concurrent scan-* requests could both observe
        # ``self._meta_analyzer is None`` and both call ``MetaAnalyzer(config)``,
        # second write wins. Constructing here at __init__ removes both issues
        # because Scanner instances themselves are not concurrently constructed
        # within a single request lifecycle.
        self._meta_analyzer = (
            MetaAnalyzer(config)
            if (config.llm_provider_api_key or is_bedrock)
            else None
        )
        self._custom_analyzers = custom_analyzers or []

        # Debug logging for analyzer initialization
        active_analyzers = []
        if self._api_analyzer:
            active_analyzers.append("API")
        if self._yara_analyzer:
            active_analyzers.append("YARA")
        if self._llm_analyzer:
            active_analyzers.append("LLM")
        if self._behavioral_analyzer:
            active_analyzers.append("Behavioral")
        if self._vt_analyzer:
            active_analyzers.append("VirusTotal")
        if self._readiness_analyzer:
            active_analyzers.append("Readiness")
        if self._prompt_defense_analyzer:
            active_analyzers.append("PromptDefense")
        for analyzer in self._custom_analyzers:
            active_analyzers.append(f"{analyzer.name}")
        logger.debug('Scanner initialized: active_analyzers="%s"', active_analyzers)

    def get_custom_analyzers(self) -> List[BaseAnalyzer]:
        """Get the list of custom analyzers used by the scanner.
        Returns:
            List[BaseAnalyzer]: List of custom analyzers.
        """
        return self._custom_analyzers

    def _validate_analyzer_requirements(
        self, requested_analyzers: List[AnalyzerEnum]
    ) -> None:
        """Validate that all requested analyzers have the required configuration.

        Args:
            requested_analyzers (List[AnalyzerEnum]): List of analyzers that were requested.

        Raises:
            ValueError: If a requested analyzer cannot be used due to missing configuration.
        """
        missing_requirements = []

        if AnalyzerEnum.API in requested_analyzers and not self._api_analyzer:
            missing_requirements.append(
                "API analyzer requested but MCP_SCANNER_API_KEY not configured"
            )

        if AnalyzerEnum.LLM in requested_analyzers and not self._llm_analyzer:
            missing_requirements.append(
                "LLM analyzer requested but MCP_SCANNER_LLM_API_KEY not configured (or AWS credentials for Bedrock models)"
            )

        if (
            AnalyzerEnum.BEHAVIORAL in requested_analyzers
            and not self._behavioral_analyzer
        ):
            missing_requirements.append(
                "Behavioral analyzer requested but MCP_SCANNER_LLM_API_KEY not configured "
                "(or AWS credentials for Bedrock models)"
            )

        if AnalyzerEnum.VIRUSTOTAL in requested_analyzers and not self._vt_analyzer:
            missing_requirements.append(
                "VirusTotal analyzer requested but VIRUSTOTAL_API_KEY not configured or scanning is disabled"
            )

        # YARA analyzer should always be available since it doesn't require API keys
        if AnalyzerEnum.YARA in requested_analyzers and not self._yara_analyzer:
            missing_requirements.append(
                "YARA analyzer requested but failed to initialize"
            )

        # READINESS analyzer should always be available since it doesn't require API keys
        if (
            AnalyzerEnum.READINESS in requested_analyzers
            and not self._readiness_analyzer
        ):
            missing_requirements.append(
                "Readiness analyzer requested but failed to initialize"
            )

        # PROMPT_DEFENSE analyzer should always be available (pure regex, no API keys)
        if (
            AnalyzerEnum.PROMPT_DEFENSE in requested_analyzers
            and not self._prompt_defense_analyzer
        ):
            missing_requirements.append(
                "Prompt Defense analyzer requested but failed to initialize"
            )

        # META analyzer is constructed at Scanner.__init__ under the same
        # ``api_key or is_bedrock`` gate as LLM / Behavioral (P1-3). Here we
        # only verify the construction succeeded — no mutation, no lazy init.
        if AnalyzerEnum.META in requested_analyzers and self._meta_analyzer is None:
            is_bedrock = self._config.llm_model and "bedrock/" in self._config.llm_model
            if not self._config.llm_provider_api_key and not is_bedrock:
                missing_requirements.append(
                    "Meta analyzer requested but MCP_SCANNER_LLM_API_KEY (or Bedrock model + AWS credentials) not configured"
                )
            else:
                # Construction was attempted in __init__ but failed silently
                # (e.g., MetaAnalyzer raised). This branch should be unreachable
                # in practice because MetaAnalyzer.__init__ raises on misconfig
                # rather than returning ``None``, but we keep it defensively.
                missing_requirements.append(
                    "Meta analyzer requested but failed to initialize at Scanner construction"
                )

        if missing_requirements:
            error_msg = (
                "Cannot proceed with scan - missing required configuration:\n"
                + "\n".join(f"  • {req}" for req in missing_requirements)
            )
            raise ValueError(error_msg)

    @staticmethod
    def _build_instructions_description_for_meta(
        result: "InstructionsScanResult", budget: int = DEFAULT_DESCRIPTION_BUDGET
    ) -> str:
        """Delegates to :func:`.meta_runner.build_instructions_description`."""
        return build_instructions_description(result, budget)

    @staticmethod
    def _build_resource_description_for_meta(
        result: ResourceScanResult, budget: int = DEFAULT_DESCRIPTION_BUDGET
    ) -> str:
        """Delegates to :func:`.meta_runner.build_resource_description`."""
        return build_resource_description(result, budget)

    # Cap on concurrent LLM round-trips during meta-analysis. Operators with
    # stricter per-tenant limits can monkey-patch this or subclass.
    _META_CONCURRENCY = DEFAULT_META_CONCURRENCY

    @property
    def _meta_runner(self) -> MetaAnalysisRunner:
        """A runner bound to the meta-analyzer and cap as they stand right now.

        Built per access rather than in ``__init__`` because both
        ``_meta_analyzer`` and ``_META_CONCURRENCY`` are documented as
        replaceable after construction.
        """
        return MetaAnalysisRunner(self._meta_analyzer, self._META_CONCURRENCY)

    async def _meta_analyze_one_tool(
        self,
        result: ToolScanResult,
        sem: "asyncio.Semaphore",
    ) -> ToolScanResult:
        """Per-tool meta-analysis worker. Bounded by ``sem``."""
        return await self._meta_runner.analyze_one(result, TOOL_SPEC, sem)

    async def _meta_analyze_one_prompt(
        self,
        result: PromptScanResult,
        sem: "asyncio.Semaphore",
    ) -> PromptScanResult:
        """Per-prompt meta-analysis worker. Bounded by ``sem``."""
        return await self._meta_runner.analyze_one(result, PROMPT_SPEC, sem)

    async def _meta_analyze_one_resource(
        self,
        result: ResourceScanResult,
        sem: "asyncio.Semaphore",
    ) -> ResourceScanResult:
        """Per-resource meta-analysis worker. Bounded by ``sem``."""
        return await self._meta_runner.analyze_one(result, RESOURCE_SPEC, sem)

    @classmethod
    def for_meta_only(cls, config: Config) -> "Scanner":
        """Construct a lightweight Scanner that only owns ``_meta_analyzer``.

        M2 fix: the static-config CLI path used to call
        ``Scanner(cfg, rules_dir=...)`` purely to gain access to
        ``apply_meta_to_results``. The full constructor instantiates
        ApiAnalyzer (HTTP client + endpoint validation), YaraAnalyzer
        (compiles every rule on disk), Behavioral / VT / Readiness /
        PromptDefense — every cycle of every static scan, despite the
        primary analysis having already run. On a 50-rule YARA tree
        with ``--enable-meta`` that's roughly half a second of pure
        startup overhead per CLI invocation, plus warning output for
        analyzers the operator never asked for.

        This factory builds a near-empty ``Scanner`` whose ``__init__``
        is bypassed (``__new__``) and only initialises the meta gate
        and concurrency bookkeeping that ``apply_meta_to_results``
        actually depends on. Behaviour is otherwise identical: the
        same ``MetaAnalyzer(config)`` constructed under the same
        ``api_key OR bedrock`` gate as the full ``__init__`` path.
        """
        instance = cls.__new__(cls)
        instance._config = config
        is_bedrock = bool(config.llm_model and "bedrock/" in config.llm_model)
        instance._meta_analyzer = (
            MetaAnalyzer(config)
            if (config.llm_provider_api_key or is_bedrock)
            else None
        )
        # Attributes apply_meta_to_results / dispatch helpers consult.
        instance._api_analyzer = None
        instance._yara_analyzer = None
        instance._llm_analyzer = None
        instance._behavioral_analyzer = None
        instance._vt_analyzer = None
        instance._readiness_analyzer = None
        instance._prompt_defense_analyzer = None
        instance._custom_analyzers = []
        return instance

    async def apply_meta_to_results(
        self,
        scan_results: Sequence[ScanResult],
        analyzers: Optional[List[AnalyzerEnum]] = None,
    ) -> List[ScanResult]:
        """Apply meta-analysis to a heterogeneous list of scan results.

        The single entrypoint the static-config CLI path uses. The CLI once
        reimplemented this loop inline, and the duplicate had already drifted
        into two real bugs: it silently dropped resource and instructions
        enrichment, and it no-op'd entirely on the IAM-only Bedrock flow.

        Args:
            scan_results: Heterogeneous list of ScanResult subclasses.
            analyzers: Analyzer set requested for the scan. If META is not in
                this list the input is returned unchanged. Defaults to
                ``[META]`` so callers that already gated on ``--enable-meta``
                upstream don't need to re-pass it.

        Returns:
            The same list, order preserved, with
            ``ScanResult.meta_filtered_findings`` populated on each enriched
            result. On per-result failure the original is kept.
        """
        if analyzers is None:
            analyzers = [AnalyzerEnum.META]
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return list(scan_results)
        return await self._meta_runner.analyze_mixed(scan_results)

    async def _attach_behavioral_source_findings(
        self,
        scan_results: List[ToolScanResult],
        analyzers: List[AnalyzerEnum],
        source_path: Optional[str] = None,
    ) -> List[ToolScanResult]:
        """Run behavioral analysis on a local source tree and merge by tool name."""
        if AnalyzerEnum.BEHAVIORAL not in analyzers or not self._behavioral_analyzer:
            return scan_results

        resolved_path = (source_path or self._behavioral_source_path or "").strip()
        if not resolved_path:
            logger.debug(
                "BEHAVIORAL analyzer requested for server scan but no source_path "
                "configured (set MCP_SCANNER_BEHAVIORAL_SOURCE_PATH or pass source_path=)"
            )
            return scan_results

        logger.debug(
            "Running behavioral source attach path=%s tool_results=%d",
            resolved_path,
            len(scan_results),
        )

        try:
            behavioral_findings = await self._behavioral_analyzer.analyze(
                resolved_path,
                context={"file_path": resolved_path},
            )
        except Exception as exc:
            logger.error(
                "Behavioral source scan failed path=%s error=%s",
                resolved_path,
                exc,
                exc_info=True,
            )
            return scan_results

        # The behavioural analyzer emits one SAFE placeholder per scanned
        # capability. ``ToolScanResult.is_safe`` is ``len(findings) == 0``, so
        # merging those rows would flip every cleanly-scanned tool to unsafe.
        placeholder_count = len(behavioral_findings)
        behavioral_findings = reportable_findings(behavioral_findings)
        placeholder_count -= len(behavioral_findings)

        if not behavioral_findings:
            logger.debug(
                "Behavioral source scan returned no findings path=%s safe_placeholders=%d",
                resolved_path,
                placeholder_count,
            )
            return scan_results

        by_tool: dict[str, list] = {}
        unmatched = []
        for finding in behavioral_findings:
            details = finding.details or {}
            tool_name = details.get("function_name") or details.get("tool_name")
            if tool_name:
                by_tool.setdefault(tool_name, []).append(finding)
            else:
                unmatched.append(finding)

        for result in scan_results:
            for finding in by_tool.pop(result.tool_name, []):
                finding.analyzer = "Behavioral"
                result.findings.append(finding)

        for findings in by_tool.values():
            unmatched.extend(findings)

        if unmatched:
            for finding in unmatched:
                finding.analyzer = "Behavioral"
            source_result = next(
                (r for r in scan_results if r.tool_name == "__behavioral_source__"),
                None,
            )
            if source_result is None:
                source_result = ToolScanResult(
                    tool_name="__behavioral_source__",
                    tool_description="Behavioral source scan",
                    status="completed",
                    analyzers=[AnalyzerEnum.BEHAVIORAL],
                    findings=[],
                )
                scan_results.append(source_result)
            source_result.findings.extend(unmatched)
        matched_count = sum(
            1 for r in scan_results for f in r.findings if f.analyzer == "Behavioral"
        )
        logger.debug(
            "Behavioral source attach complete path=%s raw_findings=%d merged=%d orphan=%d",
            resolved_path,
            len(behavioral_findings),
            matched_count,
            len(unmatched),
        )
        return scan_results

    async def _finalize_tool_scan_results(
        self,
        scan_results: List[ToolScanResult],
        analyzers: List[AnalyzerEnum],
        *,
        source_path: Optional[str] = None,
    ) -> List[ToolScanResult]:
        """Attach behavioral source findings, then run meta-analysis when enabled."""
        scan_results = await self._attach_behavioral_source_findings(
            list(scan_results), analyzers, source_path=source_path
        )
        return await self._run_meta_analysis_on_results(scan_results, analyzers)

    async def _finalize_single_tool_scan(
        self,
        result: ToolScanResult,
        analyzers: List[AnalyzerEnum],
        *,
        source_path: Optional[str] = None,
    ) -> ToolScanResult:
        """Finalize one tool scan, folding orphan behavioral findings into the result."""
        finalized = await self._finalize_tool_scan_results(
            [result], analyzers, source_path=source_path
        )
        primary = finalized[0]
        for extra in finalized[1:]:
            if extra.tool_name == "__behavioral_source__":
                primary.findings.extend(extra.findings)
                # ``meta_analysis`` audit blocks are derived from
                # ``meta_filtered_findings`` at serialization time.
                primary.meta_filtered_findings.extend(
                    list(getattr(extra, "meta_filtered_findings", []) or [])
                )
        return primary

    async def _run_meta_analysis_on_results(
        self,
        scan_results: List[ToolScanResult],
        analyzers: List[AnalyzerEnum],
    ) -> List[ToolScanResult]:
        """Meta-analyze tool results when META is enabled, preserving order."""
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return scan_results
        return await self._meta_runner.analyze_many(scan_results, TOOL_SPEC)

    async def _run_meta_analysis_on_prompt_results(
        self,
        scan_results: List[PromptScanResult],
        analyzers: List[AnalyzerEnum],
    ) -> List[PromptScanResult]:
        """Meta-analyze prompt results when META is enabled, preserving order."""
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return scan_results
        return await self._meta_runner.analyze_many(scan_results, PROMPT_SPEC)

    async def _run_meta_analysis_on_resource_results(
        self,
        scan_results: List[ResourceScanResult],
        analyzers: List[AnalyzerEnum],
    ) -> List[ResourceScanResult]:
        """Meta-analyze resource results when META is enabled, preserving order."""
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return scan_results
        return await self._meta_runner.analyze_many(scan_results, RESOURCE_SPEC)

    async def _run_meta_analysis_on_instructions_result(
        self,
        result: InstructionsScanResult,
        analyzers: List[AnalyzerEnum],
    ) -> InstructionsScanResult:
        """Meta-analyze an instructions result when META is enabled.

        Unlike the bulk runners, the disabled path clears
        ``meta_filtered_findings`` so a re-invocation cannot report a prior
        run's filtering.
        """
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            result.meta_filtered_findings = []
            return result
        return await self._meta_runner.analyze_one(result, INSTRUCTIONS_SPEC)

    async def _run_meta_analysis_on_single_tool(
        self,
        result: ToolScanResult,
        analyzers: List[AnalyzerEnum],
    ) -> ToolScanResult:
        """Run meta-analysis on a single tool scan result."""
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return result
        results = await self._run_meta_analysis_on_results([result], analyzers)
        return results[0]

    async def _run_meta_analysis_on_single_prompt(
        self,
        result: PromptScanResult,
        analyzers: List[AnalyzerEnum],
    ) -> PromptScanResult:
        """Run meta-analysis on a single prompt scan result."""
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return result
        results = await self._run_meta_analysis_on_prompt_results([result], analyzers)
        return results[0]

    async def _run_meta_analysis_on_single_resource(
        self,
        result: ResourceScanResult,
        analyzers: List[AnalyzerEnum],
    ) -> ResourceScanResult:
        """Run meta-analysis on a single resource scan result."""
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return result
        results = await self._run_meta_analysis_on_resource_results([result], analyzers)
        return results[0]

    @staticmethod
    def _is_missing_capability_error(error: Exception) -> bool:
        """Delegates to :func:`.session.is_missing_capability_error`."""
        return session_transport.is_missing_capability_error(error)

    @staticmethod
    def _server_supports_capability(session: Any, capability: str) -> Optional[bool]:
        """Delegates to :func:`.session.server_supports_capability`."""
        return session_transport.server_supports_capability(session, capability)

    @property
    def _analyzer_bundle(self) -> AnalyzerBundle:
        """The analyzers as they stand right now.

        Built per access rather than cached so callers that swap an analyzer
        after construction -- which the tests and the meta-only factory both
        do -- are honoured.
        """
        return AnalyzerBundle(
            api=self._api_analyzer,
            yara=self._yara_analyzer,
            llm=self._llm_analyzer,
            readiness=self._readiness_analyzer,
            prompt_defense=self._prompt_defense_analyzer,
            custom=self._custom_analyzers,
        )

    async def _analyze_tool(
        self,
        tool: MCPTool,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> ToolScanResult:
        """Delegates to :func:`.orchestration.analyze_tool`."""
        return await analyze_tool(self._analyzer_bundle, tool, analyzers, http_headers)

    async def _analyze_prompt(
        self,
        prompt: MCPPrompt,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> PromptScanResult:
        """Delegates to :func:`.orchestration.analyze_prompt`."""
        return await analyze_prompt(
            self._analyzer_bundle, prompt, analyzers, http_headers
        )

    async def _analyze_instructions(
        self,
        instructions: str,
        server_name: str,
        protocol_version: str,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> InstructionsScanResult:
        """Delegates to :func:`.orchestration.analyze_instructions`."""
        return await analyze_instructions(
            self._analyzer_bundle,
            instructions,
            server_name,
            protocol_version,
            analyzers,
            http_headers,
        )

    @staticmethod
    def _check_http_error_in_logs(msg: str) -> Optional[int]:
        """Delegates to :func:`.session.check_http_error_in_logs`."""
        return session_transport.check_http_error_in_logs(msg)

    @staticmethod
    async def _close_mcp_session(client_context, session):
        """Delegates to :func:`.session.close_mcp_session`."""
        return await session_transport.close_mcp_session(client_context, session)

    @staticmethod
    async def _get_mcp_session(
        server_url: str,
        auth: Optional[Auth] = None,
        *,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Tuple[Any, ClientSession]:
        """Delegates to :func:`.session.get_mcp_session`."""
        return await session_transport.get_mcp_session(
            server_url, auth, connector_id=connector_id, tenant_id=tenant_id
        )

    @staticmethod
    def _require_server_url(server_url: Optional[str]) -> None:
        """Reject a scan request that names no server."""
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

    @asynccontextmanager
    async def _remote_session(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        *,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> AsyncIterator[ClientSession]:
        """Open a session to a remote MCP server, closing it on every exit path.

        Every ``scan_remote_*`` method needs the same open/close pair, and a
        leaked session holds a live connection to the scanned server, so the
        teardown belongs in one place rather than in nine ``finally`` blocks.
        """
        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url, auth, connector_id=connector_id, tenant_id=tenant_id
            )
            yield session
        finally:
            await self._close_mcp_session(client_context, session)

    @asynccontextmanager
    async def _stdio_session(
        self, server_config: StdioServer, timeout: int, errlog: Any
    ) -> AsyncIterator[ClientSession]:
        """Launch a stdio MCP server, shutting it down on every exit path.

        The stdio counterpart of :meth:`_remote_session`; here a leak would be
        a child process rather than a connection.
        """
        client_context = None
        session = None
        try:
            client_context, session = await self._get_stdio_session(
                server_config, timeout, errlog
            )
            yield session
        finally:
            await self._close_mcp_session(client_context, session)

    async def scan_remote_server_tool(
        self,
        server_url: str,
        tool_name: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        source_path: Optional[str] = None,
    ) -> ToolScanResult:
        """Scan a specific tool on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            tool_name (str): The name of the tool to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.

        Returns:
            ToolScanResult: The result of the scan.

        Raises:
            ValueError: If the tool is not found on the server.
        """
        self._require_server_url(server_url)

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = self.DEFAULT_ANALYZERS

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._remote_session(
                server_url, auth, connector_id=connector_id, tenant_id=tenant_id
            ) as session:
                # List all tools and find the target tool
                try:
                    tool_list = await session.list_tools()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        message = f"Server '{server_url}' does not expose tools; cannot scan '{tool_name}'."
                        logger.warning(message)
                        raise ValueError(message) from e
                    raise
                target_tool = next(
                    (t for t in tool_list.tools if t.name == tool_name), None
                )

                if not target_tool:
                    raise ValueError(
                        f"Tool '{tool_name}' not found on the server at {server_url}"
                    )

                # Analyze the tool
                result = await self._analyze_tool(target_tool, analyzers, http_headers)

                return await self._finalize_single_tool_scan(
                    result, analyzers, source_path=source_path
                )

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                'Error scanning tool \'%s\' on MCP server: server="%s", error="%s"',
                tool_name,
                server_url,
                e,
            )
            raise

    async def scan_remote_server_tools(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        source_path: Optional[str] = None,
    ) -> List[ToolScanResult]:
        """Scan all tools on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            List[ToolScanResult]: The results of the scan for each tool.

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the server URL is invalid or empty.
        """
        self._require_server_url(server_url)

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = self.DEFAULT_ANALYZERS

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._remote_session(
                server_url, auth, connector_id=connector_id, tenant_id=tenant_id
            ) as session:
                # List all tools
                try:
                    tool_list = await session.list_tools()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            "Server '%s' does not expose tools: %s", server_url, e
                        )
                        return []
                    raise

                # Create analysis tasks for each tool
                scan_tasks = [
                    self._analyze_tool(tool, analyzers, http_headers)
                    for tool in tool_list.tools
                ]

                # Run all tasks concurrently
                scan_results = await asyncio.gather(*scan_tasks)

                return await self._finalize_tool_scan_results(
                    list(scan_results), analyzers, source_path=source_path
                )

        except Exception as e:
            logger.error("Error scanning server %s: %s", server_url, e)
            raise

    @staticmethod
    async def _get_stdio_session(
        server_config: StdioServer, timeout: int = 30, errlog: Any = None
    ) -> Tuple[Any, Any]:
        """Delegates to :func:`.session.get_stdio_session`."""
        return await session_transport.get_stdio_session(server_config, timeout, errlog)

    async def scan_stdio_server_tools(
        self,
        server_config: StdioServer,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
        errlog: Any = None,
        source_path: Optional[str] = None,
    ) -> List[ToolScanResult]:
        """Scan tools from a stdio MCP server.

        Args:
            server_config: The stdio server configuration
            analyzers: List of analyzers to use
            timeout: Connection timeout in seconds (defaults to config's stdio_timeout)
            errlog: Optional file-like object for stderr redirection

        Returns:
            List[ToolScanResult]: List of tool scan results
        """
        if timeout is None:
            timeout = self._config.stdio_timeout

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._stdio_session(server_config, timeout, errlog) as session:
                # List all tools
                try:
                    tool_list = await session.list_tools()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            "Stdio server '%s' does not expose tools: %s",
                            server_config.command,
                            e,
                        )
                        return []
                    raise

                # Create analysis tasks for each tool
                scan_tasks = [
                    self._analyze_tool(tool, analyzers) for tool in tool_list.tools
                ]

                # Run all tasks concurrently
                scan_results = await asyncio.gather(*scan_tasks)

                return await self._finalize_tool_scan_results(
                    list(scan_results), analyzers, source_path=source_path
                )

        except Exception as e:
            logger.error("Error scanning stdio server %s: %s", server_config.command, e)
            raise

    async def scan_stdio_server_tool(
        self,
        server_config: StdioServer,
        tool_name: str,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
        errlog: Any = None,
        source_path: Optional[str] = None,
    ) -> ToolScanResult:
        """Scan a specific tool on a stdio MCP server.

        Args:
            server_config (StdioServer): The stdio server configuration.
            tool_name (str): The name of the tool to scan.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.
            timeout (Optional[int]): Timeout for the connection (defaults to config's stdio_timeout).
            errlog: Optional file-like object for stderr redirection.

        Returns:
            ToolScanResult: The result of the scan.

        Raises:
            ValueError: If the tool is not found on the server.
        """
        if timeout is None:
            timeout = self._config.stdio_timeout
        if not server_config.command:
            raise ValueError("No command provided in stdio server configuration.")

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._stdio_session(server_config, timeout, errlog) as session:
                # List all tools and find the target tool
                try:
                    tool_list = await session.list_tools()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        message = f"Stdio server '{server_config.command}' does not expose tools; cannot scan '{tool_name}'."
                        logger.warning(message)
                        raise ValueError(message) from e
                    raise
                target_tool = next(
                    (t for t in tool_list.tools if t.name == tool_name), None
                )

                if not target_tool:
                    raise ValueError(
                        f"Tool '{tool_name}' not found on the stdio server with command {server_config.command}"
                    )

                # Analyze the tool
                result = await self._analyze_tool(target_tool, analyzers)

                return await self._finalize_single_tool_scan(
                    result, analyzers, source_path=source_path
                )

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                'Error scanning tool \'%s\' on stdio server: command="%s", error="%s"',
                tool_name,
                server_config.command,
                e,
            )
            raise

    async def scan_well_known_mcp_configs(
        self,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        auth: Optional[Auth] = None,
        expand_vars_default: Optional[str] = None,
        errlog: Any = None,
    ) -> Dict[str, List[ToolScanResult]]:
        """Scan all well-known MCP configuration files and their servers.

        Args:
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.
            auth (Optional[Auth]): Authentication configuration for remote servers.
            expand_vars_default (Optional[str]): Default variable expansion mode.
            errlog: Optional file-like object for stderr redirection of stdio servers.
                    Pass ``open(os.devnull, "w")`` to suppress server stderr.

        Returns:
            Dict[str, List[ToolScanResult]]: Dictionary mapping config file paths to scan results.
        """
        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        config_scanner = MCPConfigScanner()
        configs = await config_scanner.scan_well_known_paths()

        all_results = {}

        for config_path, config in configs.items():
            logger.debug("Scanning servers from config: %s", config_path)
            servers = config_scanner.extract_servers(config)
            config_results = []

            for server_name, server_config in servers.items():
                logger.debug("Scanning server '%s' from %s", server_name, config_path)

                try:
                    if isinstance(server_config, StdioServer):
                        # Apply default expand mode if not provided by config
                        if expand_vars_default and not server_config.expand_vars:
                            logger.debug(
                                "Applying expand_vars='%s' to server '%s'",
                                expand_vars_default,
                                server_name,
                            )
                            server_config.expand_vars = expand_vars_default
                        else:
                            logger.debug(
                                "Server '%s' expand_vars: %s (default: %s)",
                                server_name,
                                server_config.expand_vars,
                                expand_vars_default,
                            )

                        # Scan stdio server with timeout and error recovery
                        try:
                            results = await self.scan_stdio_server_tools(
                                server_config, analyzers, errlog=errlog
                            )
                            # Add server name and source to each result
                            for result in results:
                                result.server_name = server_name
                                result.server_source = config_path
                            config_results.extend(results)
                        except (
                            ConnectionError,
                            asyncio.TimeoutError,
                            asyncio.CancelledError,
                        ) as e:
                            logger.warning(
                                "Failed to connect to server '%s': %s", server_name, e
                            )
                            logger.debug("Continuing with remaining servers...")
                            continue
                    elif isinstance(server_config, RemoteServer):
                        # Scan remote server
                        try:
                            results = await self.scan_remote_server_tools(
                                server_config.url, auth=auth, analyzers=analyzers
                            )
                            # Add server name and source to each result
                            for result in results:
                                result.server_name = server_name
                                result.server_source = config_path
                            config_results.extend(results)
                        except (
                            ConnectionError,
                            asyncio.TimeoutError,
                            asyncio.CancelledError,
                        ) as e:
                            logger.warning(
                                "Failed to connect to server '%s': %s", server_name, e
                            )
                            logger.debug("Continuing with remaining servers...")
                            continue
                    else:
                        logger.warning(
                            "Unknown server type for '%s' in %s",
                            server_name,
                            config_path,
                        )

                except Exception as e:
                    logger.error(
                        "Unexpected error scanning server '%s' from %s: %s",
                        server_name,
                        config_path,
                        e,
                    )
                    logger.debug("Continuing with remaining servers...")
                    continue

            all_results[config_path] = config_results

        return all_results

    async def scan_mcp_config_file(
        self,
        config_path: str,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        auth: Optional[Auth] = None,
        expand_vars_default: Optional[str] = None,
        errlog: Any = None,
    ) -> List[ToolScanResult]:
        """Scan all servers in a specific MCP configuration file.

        Args:
            config_path (str): Path to the MCP configuration file.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to all analyzers.
            auth (Optional[Auth]): Authentication configuration for remote servers.
            expand_vars_default (Optional[str]): Default variable expansion mode.
            errlog: Optional file-like object for stderr redirection of stdio servers.
                    Pass ``open(os.devnull, "w")`` to suppress server stderr.

        Returns:
            List[ToolScanResult]: The results of scanning all servers in the config file.
        """
        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        config_scanner = MCPConfigScanner()
        config = await config_scanner.scan_specific_path(config_path)

        if not config:
            raise ValueError(f"Could not parse MCP configuration file: {config_path}")

        servers = config_scanner.extract_servers(config)
        all_results = []

        for server_name, server_config in servers.items():
            logger.debug("Scanning server '%s' from %s", server_name, config_path)

            try:
                if isinstance(server_config, StdioServer):
                    # Apply default expand mode if not provided by config
                    if expand_vars_default and not server_config.expand_vars:
                        logger.debug(
                            "Applying expand_vars='%s' to server '%s'",
                            expand_vars_default,
                            server_name,
                        )
                        server_config.expand_vars = expand_vars_default
                    else:
                        logger.debug(
                            "Server '%s' expand_vars: %s (default: %s)",
                            server_name,
                            server_config.expand_vars,
                            expand_vars_default,
                        )

                    # Scan stdio server with timeout and error recovery
                    try:
                        results = await self.scan_stdio_server_tools(
                            server_config, analyzers, errlog=errlog
                        )
                        # Add server name and source to each result
                        for result in results:
                            result.server_name = server_name
                            result.server_source = config_path
                        all_results.extend(results)
                    except (
                        ConnectionError,
                        asyncio.TimeoutError,
                        asyncio.CancelledError,
                    ) as e:
                        logger.warning(
                            "Failed to connect to server '%s': %s", server_name, e
                        )
                        logger.debug("Continuing with remaining servers...")
                        continue
                elif isinstance(server_config, RemoteServer):
                    # Scan remote server
                    try:
                        results = await self.scan_remote_server_tools(
                            server_config.url, auth=auth, analyzers=analyzers
                        )
                        # Add server name and source to each result
                        for result in results:
                            result.server_name = server_name
                            result.server_source = config_path
                        all_results.extend(results)
                    except (
                        ConnectionError,
                        asyncio.TimeoutError,
                        asyncio.CancelledError,
                    ) as e:
                        logger.warning(
                            "Failed to connect to server '%s': %s", server_name, e
                        )
                        logger.debug("Continuing with remaining servers...")
                        continue
                else:
                    logger.warning(
                        "Unknown server type for '%s' in %s", server_name, config_path
                    )

            except Exception as e:
                logger.error(
                    "Unexpected error scanning server '%s' from %s: %s",
                    server_name,
                    config_path,
                    e,
                )
                logger.debug("Continuing with remaining servers...")
                continue

        return all_results

    async def scan_remote_server_prompts(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[PromptScanResult]:
        """Scan all prompts on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            List[PromptScanResult]: The results of the scan for each prompt.

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the server URL is invalid or empty.
        """
        self._require_server_url(server_url)

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._remote_session(
                server_url, auth, connector_id=connector_id, tenant_id=tenant_id
            ) as session:
                # Capability gate: see scan_remote_server_resources for rationale.
                if self._server_supports_capability(session, "prompts") is False:
                    logger.info(
                        "Server '%s' did not advertise prompts capability; skipping prompt scan",
                        server_url,
                    )
                    return []

                # List all prompts
                try:
                    prompt_list = await session.list_prompts()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            "Server '%s' does not expose prompts: %s", server_url, e
                        )
                        return []
                    raise

                # Analyze each prompt with individual error handling
                scan_results = []
                for prompt in prompt_list.prompts:
                    try:
                        result = await self._analyze_prompt(
                            prompt, analyzers, http_headers
                        )
                        scan_results.append(result)
                    except Exception as e:
                        logger.error("Error analyzing prompt '%s': %s", prompt.name, e)
                        # Create a failed result for this prompt
                        scan_results.append(
                            PromptScanResult(
                                prompt_name=prompt.name,
                                prompt_description=prompt.description or "",
                                status="failed",
                                analyzers=[],
                                findings=[],
                            )
                        )

                # Run meta-analysis if enabled (post-pass on prompt results)
                scan_results = await self._run_meta_analysis_on_prompt_results(
                    scan_results, analyzers
                )

                return scan_results

        except Exception as e:
            logger.error("Error scanning prompts on server %s: %s", server_url, e)
            raise

    async def scan_remote_server_prompt(
        self,
        server_url: str,
        prompt_name: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> PromptScanResult:
        """Scan a specific prompt on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            prompt_name (str): The name of the prompt to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            PromptScanResult: The result of the scan.

        Raises:
            ValueError: If the prompt is not found on the server.
        """
        self._require_server_url(server_url)

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._remote_session(
                server_url, auth, connector_id=connector_id, tenant_id=tenant_id
            ) as session:
                # Capability gate (same rationale as scan_remote_server_prompts).
                if self._server_supports_capability(session, "prompts") is False:
                    message = f"Server '{server_url}' did not advertise prompts capability; cannot scan '{prompt_name}'."
                    logger.warning(message)
                    raise ValueError(message)

                # List all prompts and find the target prompt
                try:
                    prompt_list = await session.list_prompts()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        message = f"Server '{server_url}' does not expose prompts; cannot scan '{prompt_name}'."
                        logger.warning(message)
                        raise ValueError(message) from e
                    raise
                target_prompt = next(
                    (p for p in prompt_list.prompts if p.name == prompt_name), None
                )

                if not target_prompt:
                    raise ValueError(
                        f"Prompt '{prompt_name}' not found on the server at {server_url}"
                    )

                # Analyze the prompt
                result = await self._analyze_prompt(
                    target_prompt, analyzers, http_headers
                )

                # Run meta-analysis if enabled
                result = await self._run_meta_analysis_on_single_prompt(
                    result, analyzers
                )

                return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                'Error scanning prompt \'%s\' on MCP server: server="%s", error="%s"',
                prompt_name,
                server_url,
                e,
            )
            raise

    async def scan_remote_server_instructions(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> InstructionsScanResult:
        """Scan server instructions from the InitializeResult.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API, YARA, and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            InstructionsScanResult: The result of the scan.

        Raises:
            ValueError: If the server does not provide instructions.
        """
        self._require_server_url(server_url)

        # Default to all analyzers including LLM for instructions
        # Instructions benefit from semantic analysis
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._remote_session(
                server_url, auth, connector_id=connector_id, tenant_id=tenant_id
            ) as session:
                # Get the initialize result which was stored during session initialization
                init_result = getattr(session, "_init_result", None)

                if not init_result:
                    raise ValueError(
                        f"Failed to get initialization result from server at {server_url}"
                    )

                # Extract instructions from the initialize result
                instructions = getattr(init_result, "instructions", None)

                if not instructions:
                    # Return a result with no findings if instructions are not provided
                    logger.info(
                        "Server at %s does not provide instructions field", server_url
                    )
                    return InstructionsScanResult(
                        instructions="",
                        server_name=(
                            getattr(init_result.serverInfo, "name", "Unknown")
                            if hasattr(init_result, "serverInfo")
                            else "Unknown"
                        ),
                        protocol_version=getattr(
                            init_result, "protocolVersion", "Unknown"
                        ),
                        status="skipped",
                        analyzers=[],
                        findings=[],
                    )

                # Extract server info
                server_name = (
                    getattr(init_result.serverInfo, "name", "Unknown")
                    if hasattr(init_result, "serverInfo")
                    else "Unknown"
                )
                protocol_version = getattr(init_result, "protocolVersion", "Unknown")

                # Analyze the instructions
                result = await self._analyze_instructions(
                    instructions=instructions,
                    server_name=server_name,
                    protocol_version=protocol_version,
                    analyzers=analyzers,
                    http_headers=http_headers,
                )

                # Run meta-analysis if enabled
                result = await self._run_meta_analysis_on_instructions_result(
                    result, analyzers
                )

                return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                'Error scanning instructions on MCP server: server="%s", error="%s"',
                server_url,
                e,
            )
            raise

    async def scan_stdio_server_prompts(
        self,
        server_config: StdioServer,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
        errlog: Any = None,
    ) -> List[PromptScanResult]:
        """Scan prompts from a stdio MCP server.

        Args:
            server_config: The stdio server configuration
            analyzers: List of analyzers to use (defaults to API and LLM)
            timeout: Connection timeout in seconds
            errlog: Optional file-like object for stderr redirection.
                    Pass ``open(os.devnull, "w")`` to suppress server stderr.
            timeout: Connection timeout in seconds (defaults to config's stdio_timeout)

        Returns:
            List of prompt scan results
        """
        if timeout is None:
            timeout = self._config.stdio_timeout

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._stdio_session(server_config, timeout, errlog) as session:
                # List all prompts
                try:
                    prompt_list = await session.list_prompts()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            "Stdio server '%s' does not expose prompts: %s",
                            server_config.command,
                            e,
                        )
                        return []
                    raise

                # Create analysis tasks for each prompt
                scan_tasks = [
                    self._analyze_prompt(prompt, analyzers)
                    for prompt in prompt_list.prompts
                ]

                # Run all tasks concurrently
                scan_results = await asyncio.gather(*scan_tasks)

                # Run meta-analysis if enabled (post-pass on prompt results)
                scan_results = await self._run_meta_analysis_on_prompt_results(
                    list(scan_results), analyzers
                )

                return scan_results

        except Exception as e:
            logger.error(
                "Error scanning prompts on stdio server %s: %s",
                server_config.command,
                e,
            )
            raise

    async def scan_stdio_server_prompt(
        self,
        server_config: StdioServer,
        prompt_name: str,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
        errlog: Any = None,
    ) -> PromptScanResult:
        """Scan a specific prompt on a stdio MCP server.

        Args:
            server_config (StdioServer): The stdio server configuration.
            prompt_name (str): The name of the prompt to scan.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            timeout (Optional[int]): Timeout for the connection.
            errlog: Optional file-like object for stderr redirection.
                    Pass ``open(os.devnull, "w")`` to suppress server stderr.
            timeout (Optional[int]): Timeout for the connection (defaults to config's stdio_timeout).

        Returns:
            PromptScanResult: The result of the scan.

        Raises:
            ValueError: If the prompt is not found on the server.
        """
        if timeout is None:
            timeout = self._config.stdio_timeout
        if not server_config.command:
            raise ValueError("No command provided in stdio server configuration.")

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._stdio_session(server_config, timeout, errlog) as session:
                # List all prompts and find the target prompt
                try:
                    prompt_list = await session.list_prompts()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        message = f"Stdio server '{server_config.command}' does not expose prompts; cannot scan '{prompt_name}'."
                        logger.warning(message)
                        raise ValueError(message) from e
                    raise
                target_prompt = next(
                    (p for p in prompt_list.prompts if p.name == prompt_name), None
                )

                if not target_prompt:
                    raise ValueError(
                        f"Prompt '{prompt_name}' not found on the stdio server with command {server_config.command}"
                    )

                # Analyze the prompt
                result = await self._analyze_prompt(target_prompt, analyzers)

                # Run meta-analysis if enabled
                result = await self._run_meta_analysis_on_single_prompt(
                    result, analyzers
                )

                return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                'Error scanning prompt \'%s\' on stdio server: command="%s", error="%s"',
                prompt_name,
                server_config.command,
                e,
            )
            raise

    async def _analyze_resource(
        self,
        resource_content: str,
        resource_uri: str,
        resource_name: str,
        resource_description: str,
        resource_mime_type: str,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> ResourceScanResult:
        """Delegates to :func:`.orchestration.analyze_resource`."""
        return await analyze_resource(
            self._analyzer_bundle,
            resource_content,
            resource_uri,
            resource_name,
            resource_description,
            resource_mime_type,
            analyzers,
            http_headers,
        )

    async def scan_remote_server_resources(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        allowed_mime_types: Optional[List[str]] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[ResourceScanResult]:
        """Scan all resources on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.
            allowed_mime_types (Optional[List[str]]): List of allowed MIME types to scan. Defaults to text/plain and text/html.

        Returns:
            List[ResourceScanResult]: The results of the scan for each resource.
            A resource that could not be read or analyzed appears with a
            "skipped" or "failed" status rather than being dropped.

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the server URL is invalid or empty.
        """
        self._require_server_url(server_url)

        # Default to API and LLM analyzers for resources
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        if allowed_mime_types is None:
            allowed_mime_types = list(DEFAULT_ALLOWED_MIME_TYPES)

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._remote_session(
                server_url, auth, connector_id=connector_id, tenant_id=tenant_id
            ) as session:
                # Capability gate: if the InitializeResult didn't advertise
                # resources support, don't bother calling list_resources — many
                # real servers return HTTP 404 for the unsupported method which
                # the MCP SDK relabels as "Session terminated".
                if self._server_supports_capability(session, "resources") is False:
                    logger.info(
                        "Server '%s' did not advertise resources capability; skipping resource scan",
                        server_url,
                    )
                    return []

                # List all resources
                try:
                    resource_list = await session.list_resources()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            "Server '%s' does not expose resources: %s", server_url, e
                        )
                        return []
                    raise

                results = []
                for resource in resource_list.resources:
                    if not mime_type_allowed(resource, allowed_mime_types):
                        logger.info(
                            "Skipping resource '%s' with MIME type '%s'",
                            resource.uri,
                            resource.mimeType,
                        )
                        results.append(resource_placeholder(resource, "skipped"))
                        continue

                    results.append(
                        await self._read_and_analyze_resource(
                            session,
                            resource,
                            analyzers,
                            http_headers,
                            absorb_analysis_errors=True,
                        )
                    )

                # Run meta-analysis if enabled (post-pass on all resource results)
                results = await self._run_meta_analysis_on_resource_results(
                    results, analyzers
                )

                return results

        except Exception as e:
            logger.error("Error scanning resources on server %s: %s", server_url, e)
            raise

    async def _read_and_analyze_resource(
        self,
        session: Any,
        resource: Any,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict],
        *,
        absorb_analysis_errors: bool,
    ) -> ResourceScanResult:
        """Read one resource and analyze it, turning read failures into placeholders.

        ``absorb_analysis_errors`` reflects a difference between the two
        callers that predates this refactor: a whole-server scan must not abort
        because one resource failed to analyze, while a caller who asked for
        one specific resource gets the exception. Note that an absorbed failure
        becomes a findings-free result, which downstream reads as safe.
        """
        try:
            contents = await session.read_resource(resource.uri)
        except asyncio.TimeoutError:
            logger.error("Timeout reading resource '%s'", resource.uri)
            return resource_placeholder(resource, "failed")
        except Exception as e:
            logger.error("Error reading resource '%s': %s", resource.uri, e)
            return resource_placeholder(resource, "failed")

        text_content = extract_resource_text(contents, resource.uri)
        if text_content is None:
            return resource_placeholder(resource, "failed")
        if not text_content:
            logger.info("No text content found for resource '%s'", resource.uri)
            return resource_placeholder(resource, "skipped")

        try:
            return await self._analyze_resource(
                text_content,
                resource.uri,
                resource.name or "",
                resource.description or "",
                resource.mimeType or "unknown",
                analyzers,
                http_headers,
            )
        except Exception as e:
            if not absorb_analysis_errors:
                raise
            logger.error("Error analyzing resource '%s': %s", resource.uri, e)
            return resource_placeholder(resource, "failed")

    async def scan_remote_server_resource(
        self,
        server_url: str,
        resource_uri: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        allowed_mime_types: Optional[List[str]] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> ResourceScanResult:
        """Scan a specific resource on an MCP server.

        Args:
            server_url (str): The URL of the MCP server to scan.
            resource_uri (str): The URI of the resource to scan.
            auth (Optional[Auth]): Authentication configuration for the server. Defaults to None.
            analyzers (Optional[List[AnalyzerEnum]]): List of analyzers to run. Defaults to API and LLM.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.
            allowed_mime_types (Optional[List[str]]): List of allowed MIME types to scan. Defaults to text/plain and text/html.

        Returns:
            ResourceScanResult: The result of the scan.

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the resource is not found on the server or server URL is invalid.
        """
        self._require_server_url(server_url)

        if not resource_uri:
            raise ValueError(
                "No resource URI provided. Please specify a valid resource URI."
            )

        # Default to API and LLM analyzers for resources
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        if allowed_mime_types is None:
            allowed_mime_types = list(DEFAULT_ALLOWED_MIME_TYPES)

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        try:
            async with self._remote_session(
                server_url, auth, connector_id=connector_id, tenant_id=tenant_id
            ) as session:
                # Capability gate (same rationale as scan_remote_server_resources).
                if self._server_supports_capability(session, "resources") is False:
                    message = f"Server '{server_url}' did not advertise resources capability; cannot scan '{resource_uri}'."
                    logger.warning(message)
                    raise ValueError(message)

                # List all resources to find the target
                try:
                    resource_list = await session.list_resources()
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        message = f"Server '{server_url}' does not expose resources; cannot scan '{resource_uri}'."
                        logger.warning(message)
                        raise ValueError(message) from e
                    raise

                target_resource = next(
                    (r for r in resource_list.resources if str(r.uri) == resource_uri),
                    None,
                )
                if not target_resource:
                    raise ValueError(
                        f"Resource '{resource_uri}' not found on server {server_url}"
                    )

                if not mime_type_allowed(target_resource, allowed_mime_types):
                    logger.info(
                        "Resource '%s' has unsupported MIME type '%s'",
                        resource_uri,
                        target_resource.mimeType,
                    )
                    return resource_placeholder(target_resource, "skipped")

                result = await self._read_and_analyze_resource(
                    session,
                    target_resource,
                    analyzers,
                    http_headers,
                    absorb_analysis_errors=False,
                )

                # Run meta-analysis if enabled
                return await self._run_meta_analysis_on_single_resource(
                    result, analyzers
                )

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                "Error scanning resource '%s' on server %s: %s",
                resource_uri,
                server_url,
                e,
            )
            raise
