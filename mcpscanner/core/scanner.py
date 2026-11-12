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
import contextvars
import functools
import json
import logging as stdlib_logging
import os
import shlex
import shutil
import sys
import time
import warnings
from contextlib import asynccontextmanager, suppress
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
)
import httpx

# MCP client imports
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client, create_mcp_http_client
from mcp.types import PaginatedRequestParams
from mcp.types import Tool as MCPTool, Prompt as MCPPrompt
from mcp import StdioServerParameters

try:
    from mcp.shared.exceptions import MCPError as McpError
except ImportError:  # pragma: no cover - mcp < 2.0
    from mcp.shared.exceptions import McpError  # type: ignore[no-redef]

try:
    from mcp_types import METHOD_NOT_FOUND, UNSUPPORTED_PROTOCOL_VERSION
except ImportError:  # pragma: no cover - mcp < 2.0
    METHOD_NOT_FOUND = -32601
    UNSUPPORTED_PROTOCOL_VERSION = -32022


from ..config.config import Config
from ..config.constants import MCPScannerConstants
from ..utils.analyzer_errors import build_infrastructure_error_finding
from ..utils.logging_config import get_logger
from ..utils.proxy_relay import is_hybrid_connector_id, prepare_mcp_dial
from ..utils.command_utils import (
    build_env_for_expansion,
    decide_windows_semantics,
    expand_text,
    normalize_and_expand_command_args,
    split_embedded_args,
    resolve_executable_path,
)
from .analyzers.api_analyzer import ApiAnalyzer
from .analyzers.base import BaseAnalyzer, SecurityFinding
from .analyzers.llm_analyzer import LLMAnalyzer
from .analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis
from .analyzers.yara_analyzer import YaraAnalyzer
from .analyzers.behavioral import BehavioralCodeAnalyzer
from .analyzers.virustotal_analyzer import VirusTotalAnalyzer
from .analyzers.prompt_defense_analyzer import PromptDefenseAnalyzer
from .analyzers.readiness import ReadinessAnalyzer
from .analyzers.readiness.readiness_analyzer import ReadinessCheckFailure
from .analyzers.schema_reference_analyzer import SchemaReferenceAnalyzer
from .auth import (
    Auth,
    AuthType,
    create_oauth_provider_from_auth,
)
from .exceptions import (
    MCPConnectionError,
    MCPAuthenticationError,
    MCPServerNotFoundError,
)
from .models import AnalyzerEnum
from .mcp_models import StdioServer, RemoteServer
from ..config.config_parser import MCPConfigScanner
from .result import (
    ScanResult,
    ToolScanResult,
    PromptScanResult,
    ResourceScanResult,
    InstructionsScanResult,
)

ScannerFactory = Callable[[List[AnalyzerEnum], Optional[str]], "Scanner"]


class ScanListNotice:
    """Catalog size emitted before per-item scan results."""

    def __init__(self, count: int, list_complete: bool) -> None:
        self.count = count
        self.list_complete = list_complete


_cleanup_depth: contextvars.ContextVar[int] = contextvars.ContextVar(
    "mcp_scanner_cleanup_depth", default=0
)


def _suspend_task_cancellation() -> int:
    """Drop a pending cancellation so the next cleanup await can run.

    On Python 3.11 and 3.12, calling ``cancel`` again after ``uncancel``
    sets ``_must_cancel``, and the next ``uncancel`` does not clear it.
    Cleanup therefore does not re-cancel the task. The outermost cleanup
    re-raises ``CancelledError`` after every cleanup await has finished.
    """
    current = asyncio.current_task()
    if current is None:
        return 0
    count = 0
    while current.cancelling():
        current.uncancel()
        count += 1
    return count


@asynccontextmanager
async def _cancellation_window():
    """Run cleanup awaits, then re-raise if this task was cancelled.

    Several cleanup steps can share one window. A step must not re-raise
    on its own, or the next step in the same finally would be skipped.
    """
    token = _cleanup_depth.set(_cleanup_depth.get() + 1)
    count = _suspend_task_cancellation()
    try:
        yield
    finally:
        _cleanup_depth.reset(token)
        if count and sys.exc_info()[0] is None:
            raise asyncio.CancelledError()


async def _await_cancelled_tasks(tasks: Sequence[asyncio.Task]) -> None:
    """Cancel outstanding tasks and wait, even during an outer cancellation.

    On Python 3.11 a pending cancellation is raised at the next await, which
    would skip this wait and close the MCP session while RPCs are still in
    flight. The count is cleared for the wait. The cancellation is raised
    again after the wait, unless an outer cleanup window will do that.
    """
    pending = [task for task in tasks if task is not None and not task.done()]
    for task in pending:
        task.cancel()
    if not pending:
        return

    async def wait() -> None:
        """Wait for the cancelled tasks, including ones that already failed."""
        await asyncio.gather(*pending, return_exceptions=True)

    if _cleanup_depth.get():
        await wait()
        return
    async with _cancellation_window():
        await wait()


def _signal_stream_end(queue: asyncio.Queue, finished: object) -> None:
    """Wake a stream consumer without waiting for a full queue."""
    try:
        queue.put_nowait(finished)
    except asyncio.QueueFull:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            return
        try:
            queue.put_nowait(finished)
        except asyncio.QueueFull:
            return


class _SameTaskAsyncIter:
    """Async iterator whose cleanup runs on the task that enters it.

    ``async for`` does not close a generator on ``break``. The finalizer
    then closes the MCP session from another task, and anyio refuses to
    exit that cancel scope. Use ``async with`` (or ``aclose``) so the
    session closes on this task.
    """

    def __init__(self, agen: AsyncIterator[Any]) -> None:
        self._agen = agen

    def __aiter__(self) -> "_SameTaskAsyncIter":
        return self

    async def __anext__(self) -> Any:
        return await anext(self._agen)

    async def aclose(self) -> None:
        """Close the wrapped generator on the calling task."""
        close = getattr(self._agen, "aclose", None)
        if close is not None:
            await close()

    async def __aenter__(self) -> "_SameTaskAsyncIter":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        await self.aclose()
        return False


class _HeldMcpSession:
    """An MCP session opened before the HTTP body starts.

    The stream generator closes it when the body runs. The HTTP response
    also closes it, because a failed status write never starts that
    generator and ``aclose`` on a generator that never ran skips its body.
    """

    def __init__(self, scanner: "Scanner", client_context: Any, session: Any) -> None:
        self.session = session
        self._scanner = scanner
        self._client_context = client_context
        self._lock = asyncio.Lock()
        self._closed = False

    async def close(self) -> None:
        """Close the session once, including while this task is being cancelled."""
        if self._closed:
            return

        async def close_session() -> None:
            """Close the held session once the lock is free."""
            async with self._lock:
                if self._closed:
                    return
                await self._scanner._close_mcp_session(
                    self._client_context, self.session
                )
                self._closed = True

        if _cleanup_depth.get():
            await close_session()
            return
        async with _cancellation_window():
            await close_session()


logger = get_logger(__name__)


class _ItemBudget:
    """One deadline shared by every analyzer call and the meta pass."""

    def __init__(self) -> None:
        self.limit = float(MCPScannerConstants.ITEM_DEADLINE_SECONDS)
        self.llm_extension_used = False
        self._paused_at: Optional[float] = None
        self._pause_depth = 0
        if self.limit <= 0:
            self.deadline = None
        else:
            self.deadline = time.monotonic() + self.limit

    @property
    def paused(self) -> bool:
        """True while this item is waiting for a shared slot."""
        return self._pause_depth > 0

    def pause(self) -> None:
        """Stop the deadline while this item waits for a shared slot."""
        if self.deadline is None:
            return
        if self._pause_depth == 0:
            self._paused_at = time.monotonic()
        self._pause_depth += 1

    def resume(self) -> None:
        """Restart the deadline after a shared slot is acquired."""
        if self.deadline is None or self._pause_depth == 0:
            return
        self._pause_depth -= 1
        if self._pause_depth == 0 and self._paused_at is not None:
            self.deadline += time.monotonic() - self._paused_at
            self._paused_at = None

    def remaining(self) -> Optional[float]:
        """Seconds left, ``None`` when the deadline is disabled, else ``>= 0``."""
        if self.deadline is None:
            return None
        now = self._paused_at if self._paused_at is not None else time.monotonic()
        return max(0.0, self.deadline - now)

    def wait_limit(self, allowance: float) -> Optional[float]:
        """How long the next call may run.

        The first LLM-family call may run for its own retry budget when that
        is longer than the time left. Later calls on this item use only the
        time left, so those budgets do not stack.
        """
        remaining = self.remaining()
        if remaining is None:
            return None
        if remaining <= 0:
            return 0.0
        if allowance > 0 and not self.llm_extension_used:
            self.llm_extension_used = True
            return max(remaining, allowance)
        return remaining


_item_budget_var: contextvars.ContextVar[Optional[_ItemBudget]] = (
    contextvars.ContextVar(
        "mcpscanner_item_budget",
        default=None,
    )
)


def _discard_awaitable(awaitable: Any) -> None:
    """Drop a coroutine that the item budget will not start."""
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()
        return
    cancel = getattr(awaitable, "cancel", None)
    if callable(cancel):
        cancel()


def _share_item_budget(
    method: Callable[..., Awaitable[Any]],
) -> Callable[..., Awaitable[Any]]:
    """Give every analyzer call inside ``method`` the same item deadline."""

    @functools.wraps(method)
    async def wrapped(self: "Scanner", *args: Any, **kwargs: Any) -> Any:
        async with self._item_budget_scope():
            return await method(self, *args, **kwargs)

    return wrapped


class CoverageLimitExceeded(Exception):
    """A prompt or resource exceeded a configured size or count budget.

    The scan must not report this as a complete clean result. ``excerpt`` is
    the bounded evidence that was retained; analyzers are not given the
    unbounded body.
    """

    def __init__(
        self,
        message: str,
        *,
        excerpt: str = "",
        observed: int = 0,
        limit: int = 0,
    ):
        super().__init__(message)
        self.excerpt = excerpt
        self.observed = observed
        self.limit = limit


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
        self._schema_analyzer = SchemaReferenceAnalyzer()
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
        logger.debug(f'Scanner initialized: active_analyzers="{active_analyzers}"')

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
        result: "InstructionsScanResult", budget: int = 8000
    ) -> str:
        """Synthesize a description string for instructions meta-analysis.

        M3 fix: prior to this the meta helper truncated to a hard 500-byte
        slice of ``result.instructions``, leaving the meta-analyzer
        unable to see evidence past that boundary. Mirror the
        resource-side budgeted-snippet shape so behaviour is consistent
        across entity types.

        Returns an empty string when ``result.instructions`` is falsy
        (no risk of TypeError on ``None``); otherwise the full text up
        to ``budget`` bytes with a clear truncation marker.
        """
        text = (getattr(result, "instructions", "") or "").strip()
        if not text:
            return ""
        if len(text) <= budget:
            return text
        elided = len(text) - budget
        return text[:budget] + f"... [instructions truncated, {elided} bytes elided]"

    @staticmethod
    def _coerce_prompt_message_content(content: Any) -> str:
        """Extract plain text from an MCP prompt message content object."""
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if hasattr(content, "text"):
            text = getattr(content, "text", None)
            return text if isinstance(text, str) else str(text or "")
        if isinstance(content, list):
            parts = [Scanner._coerce_prompt_message_content(item) for item in content]
            return "\n".join(part for part in parts if part)
        return str(content)

    @classmethod
    def _extract_prompt_messages_text(cls, get_prompt_result: Any) -> str:
        """Flatten ``prompts/get`` message bodies into one analyzable string."""
        messages = getattr(get_prompt_result, "messages", None) or []
        blocks: List[str] = []
        for message in messages:
            role = getattr(message, "role", "user")
            text = cls._coerce_prompt_message_content(
                getattr(message, "content", None)
            ).strip()
            if text:
                blocks.append(f"[{role}]\n{text}")
        return "\n\n".join(blocks)

    @staticmethod
    def _default_prompt_arguments(prompt: MCPPrompt) -> Dict[str, str]:
        """Build empty argument values for ``prompts/get`` when args are optional."""
        arguments: Dict[str, str] = {}
        for arg in getattr(prompt, "arguments", None) or []:
            name = getattr(arg, "name", None)
            if name:
                arguments[name] = ""
        return arguments

    async def _resolve_prompt_messages_text(
        self, session: ClientSession, prompt: MCPPrompt
    ) -> Tuple[str, Optional[Exception]]:
        """Fetch rendered prompt messages via ``prompts/get`` for analysis.

        Returns:
            Tuple of (message text, fetch error). On failure the text is empty
            and the error is set so callers do not treat metadata-only as complete.
        """
        try:
            arguments = self._default_prompt_arguments(prompt)
            get_prompt_result = await asyncio.wait_for(
                session.get_prompt(prompt.name, arguments=arguments),
                timeout=MCPScannerConstants.MCP_CONTENT_READ_TIMEOUT_SECONDS,
            )
            return self._extract_prompt_messages_text(get_prompt_result), None
        except Exception as e:
            logger.warning(f"Could not fetch prompt messages for '{prompt.name}': {e}")
            return "", e

    @staticmethod
    def _normalize_mime_type(mime: Optional[str]) -> str:
        """Normalize a MIME type for allowlist comparison (base type, lowercase)."""
        if not mime:
            return ""
        base = mime.split(";", 1)[0].strip().lower()
        return base

    @staticmethod
    def _advertised_resource_mime(resource: Any) -> Optional[str]:
        """Read the SDK attribute on both MCP 2.x and legacy resource models."""
        return getattr(resource, "mime_type", None) or getattr(
            resource, "mimeType", None
        )

    @classmethod
    def _resource_mime_is_allowed(
        cls, effective_mime: str, allowed_mime_types: List[str]
    ) -> bool:
        """Whether a resolved MIME type may be analyzed."""
        mime = cls._normalize_mime_type(effective_mime)
        if not mime or mime == "unknown":
            return True
        allowed = {cls._normalize_mime_type(m) for m in allowed_mime_types}
        return mime in allowed

    @staticmethod
    def _bound_text(text: str, limit: int) -> tuple[str, bool]:
        """Return ``(excerpt, truncated)``.

        ``limit`` is a character budget. The excerpt is the only text that
        may be retained or passed to an analyzer.
        """
        if not text or limit <= 0:
            return "", bool(text)
        if len(text) <= limit:
            return text, False
        return text[:limit], True

    @staticmethod
    def _apply_body_budget(
        text: str, per_item_limit: int, remaining: int
    ) -> tuple[str, Optional["CoverageLimitExceeded"]]:
        """Accept ``text`` only when it fits both the per-item and aggregate budgets."""
        observed = len(text or "")
        cap = min(per_item_limit, remaining)
        if observed > per_item_limit or observed > remaining:
            excerpt, _ = Scanner._bound_text(text or "", max(cap, 0))
            return excerpt, CoverageLimitExceeded(
                (
                    f"body size {observed} exceeds limit {per_item_limit} "
                    f"(aggregate remaining {remaining})"
                ),
                excerpt=excerpt,
                observed=observed,
                limit=per_item_limit,
            )
        return text or "", None

    @staticmethod
    def _consume_rejected_budget(observed: int, excerpt: str, remaining: int) -> int:
        """Aggregate budget left after a body that was not analyzed.

        A body larger than the remaining aggregate ends further collection.
        A body rejected only by the per-item cap still charges the retained
        excerpt, so a run of oversized responses cannot continue unbounded.
        """
        if observed > remaining:
            return 0
        return remaining - len(excerpt)

    def _prompt_messages_fetch_failure_result(
        self,
        prompt: MCPPrompt,
        error: Exception,
        analyzers: List[AnalyzerEnum],
    ) -> PromptScanResult:
        """Build a failed prompt result when ``prompts/get`` is unavailable."""
        finding = build_infrastructure_error_finding(
            analyzer_name="MCP",
            subject=prompt.name,
            error=error,
            context="local",
            safe_reason=(
                "coverage_limit" if isinstance(error, CoverageLimitExceeded) else None
            ),
        )
        active = [a for a in analyzers if a != AnalyzerEnum.META]
        excerpt = ""
        if isinstance(error, CoverageLimitExceeded):
            excerpt = error.excerpt
        return PromptScanResult(
            prompt_name=prompt.name,
            prompt_description=prompt.description or "",
            status="failed",
            analyzers=active,
            findings=[finding],
            prompt_messages_text=excerpt,
        )

    async def _collect_prompt_message_bodies(
        self,
        session: ClientSession,
        prompts: Sequence[MCPPrompt],
        on_item: Optional[
            Callable[[int, Tuple[MCPPrompt, str, Optional[Exception]]], None]
        ] = None,
    ) -> List[Tuple[MCPPrompt, str, Optional[Exception]]]:
        """Fetch ``prompts/get`` bodies in list order, within count and byte budgets.

        Up to the scan limit are fetched at once. Bytes and the prompt count
        are committed in list order, and a prompt is not fetched once either
        budget is already exhausted. ``on_item`` runs as soon as an item is
        committed so analysis overlaps later fetches.
        """
        collected: List[Tuple[MCPPrompt, str, Optional[Exception]]] = []
        remaining = MCPScannerConstants.MAX_PROMPT_RESOURCE_AGGREGATE_CHARS
        max_prompts = MCPScannerConstants.MAX_PROMPTS_PER_SCAN
        accepted = 0

        def commit(
            item: Tuple[MCPPrompt, str, Optional[Exception]],
        ) -> None:
            collected.append(item)
            if on_item is not None:
                on_item(len(collected) - 1, item)

        fetch_limit = self._remote_scan_limit()
        scheduled: Dict[int, asyncio.Task] = {}
        cursor = 0
        in_flight = 0

        def schedule_fetches() -> None:
            nonlocal cursor, in_flight
            while (
                len(scheduled) < fetch_limit
                and cursor < len(prompts)
                and remaining > 0
                and accepted + in_flight < max_prompts
            ):
                index = cursor
                prompt = prompts[index]
                cursor += 1
                in_flight += 1
                scheduled[index] = asyncio.create_task(
                    self._resolve_prompt_messages_text(session, prompt)
                )

        async def drop_fetch(task: asyncio.Task) -> None:
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await task

        def budget_item(
            prompt: MCPPrompt,
        ) -> Tuple[MCPPrompt, str, Optional[Exception]]:
            return (
                prompt,
                "",
                CoverageLimitExceeded(
                    (
                        "prompt scan budget exhausted "
                        f"(accepted={accepted}, remaining={remaining})"
                    ),
                    observed=accepted,
                    limit=max_prompts,
                ),
            )

        try:
            schedule_fetches()
            for index, prompt in enumerate(prompts):
                task = scheduled.pop(index, None)
                if accepted >= max_prompts or remaining <= 0:
                    if task is not None:
                        await drop_fetch(task)
                        in_flight -= 1
                    commit(budget_item(prompt))
                    continue
                if task is None:
                    commit(budget_item(prompt))
                    continue
                text, fetch_error = await task
                in_flight -= 1
                accepted += 1
                if fetch_error is not None:
                    commit((prompt, "", fetch_error))
                else:
                    bounded, limit_error = self._apply_body_budget(
                        text,
                        MCPScannerConstants.MAX_PROMPT_BODY_CHARS,
                        remaining,
                    )
                    if limit_error is not None:
                        commit((prompt, bounded, limit_error))
                        remaining = self._consume_rejected_budget(
                            len(text), bounded, remaining
                        )
                    else:
                        remaining -= len(bounded)
                        commit((prompt, bounded, None))
                if remaining <= 0 or accepted >= max_prompts:
                    for pending in scheduled.values():
                        pending.cancel()
                else:
                    self._refill_prefetch(schedule_fetches, True)
            return collected
        finally:
            await _await_cancelled_tasks(list(scheduled.values()))

    async def _analyze_one_prompt_for_scan(
        self,
        prompt: MCPPrompt,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict],
        prompt_messages_text: str,
        fetch_error: Optional[Exception],
        scan_sem: asyncio.Semaphore,
        meta_sem: asyncio.Semaphore,
    ) -> PromptScanResult:
        """Analyze one prompt, including a fetch failure, then run meta.

        Fetch failures do not take a scan slot. Both paths run meta when
        it is enabled, so the batch helper and the streaming fetch path
        stay on the same code.
        """

        async def analyze() -> PromptScanResult:
            if fetch_error is not None:
                return self._prompt_messages_fetch_failure_result(
                    prompt, fetch_error, analyzers
                )
            try:
                return await self._analyze_prompt(
                    prompt,
                    analyzers,
                    http_headers,
                    prompt_messages_text=prompt_messages_text,
                )
            except Exception as e:
                logger.error(
                    "Error analyzing prompt '%s': %s",
                    prompt.name,
                    type(e).__name__,
                )
                finding = build_infrastructure_error_finding(
                    analyzer_name="MCP",
                    subject=prompt.name,
                    error=e,
                    context="local",
                )
                return PromptScanResult(
                    prompt_name=prompt.name,
                    prompt_description=prompt.description or "",
                    status="failed",
                    analyzers=[],
                    findings=[finding],
                    prompt_messages_text=prompt_messages_text,
                )

        async def meta(result: PromptScanResult) -> PromptScanResult:
            return await self._meta_analyze_one_prompt(result, meta_sem)

        use_meta = AnalyzerEnum.META in analyzers and self._meta_analyzer is not None
        return await self._analyze_and_meta_item(
            None if fetch_error is not None else scan_sem,
            analyze,
            meta if use_meta else None,
        )

    async def _fetch_and_analyze_prompts(
        self,
        session: ClientSession,
        prompts: Sequence[MCPPrompt],
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
        sink: Optional[asyncio.Queue] = None,
    ) -> List[PromptScanResult]:
        """Fetch prompts in order and analyze each body as soon as it is committed."""
        prompts = list(prompts)
        results: List[Optional[PromptScanResult]] = [None] * len(prompts)
        sem = asyncio.Semaphore(self._remote_scan_limit())
        meta_sem = asyncio.Semaphore(self._META_CONCURRENCY)
        tasks: List[asyncio.Task] = []

        async def run(
            index: int, prompt: MCPPrompt, text: str, err: Optional[Exception]
        ) -> None:
            results[index] = await self._analyze_one_prompt_for_scan(
                prompt,
                analyzers,
                http_headers,
                text,
                err,
                sem,
                meta_sem,
            )
            if sink is not None and results[index] is not None:
                await sink.put(results[index])

        def on_item(
            index: int, item: Tuple[MCPPrompt, str, Optional[Exception]]
        ) -> None:
            prompt, text, err = item
            tasks.append(asyncio.create_task(run(index, prompt, text, err)))

        try:
            await self._collect_prompt_message_bodies(session, prompts, on_item=on_item)
            if tasks:
                await asyncio.gather(*tasks)
            missing = [index for index, result in enumerate(results) if result is None]
            if missing:
                raise RuntimeError(f"prompt scan left indexes unsettled: {missing}")
            return results
        finally:
            await _await_cancelled_tasks(tasks)

    @classmethod
    def _extract_resource_read_result(
        cls,
        read_resource_result: Any,
        list_mime_type: Optional[str] = None,
    ) -> tuple[str, str, bool, bool, int]:
        """Extract text and effective MIME type from ``resources/read`` result.

        The MIME type on the read content wins over ``resources/list``
        metadata. The list MIME is used only when the read response does
        not provide one. Disagreeing MIME types across content blocks
        resolve to ``conflicting``, which fails a normal allowlist.

        Text concatenation stops at ``MAX_RESOURCE_BODY_CHARS``.

        Returns:
            Tuple of (text, effective_mime, binary_only, truncated, observed).
            ``binary_only`` is True when contents had no usable text.
            ``truncated`` is True when further text was dropped for the
            per-resource budget. Callers must not treat that as complete.
            ``observed`` is the total text length seen, including text that
            was not retained.
        """
        contents = getattr(read_resource_result, "contents", None) or []
        text_content = ""
        read_mimes: List[str] = []
        saw_binary = False
        truncated = False
        observed = 0
        limit = MCPScannerConstants.MAX_RESOURCE_BODY_CHARS

        for content in contents:
            if hasattr(content, "text") and content.text:
                piece = content.text
                observed += len(piece)
                raw_mime = cls._advertised_resource_mime(content)
                if raw_mime:
                    read_mimes.append(raw_mime)
                room = limit - len(text_content)
                if room <= 0:
                    truncated = True
                    continue
                if len(piece) > room:
                    text_content += piece[:room]
                    truncated = True
                else:
                    text_content += piece
            elif hasattr(content, "blob") and content.blob:
                saw_binary = True
                logger.info("Skipping binary blob segment in resource contents")
                continue

        effective_mime = cls._resolve_effective_mime(list_mime_type, read_mimes)
        if not text_content.strip() and saw_binary:
            return "", effective_mime, True, False, observed
        return text_content, effective_mime, False, truncated, observed

    @classmethod
    def _resolve_effective_mime(
        cls, list_mime_type: Optional[str], read_mimes: List[str]
    ) -> str:
        """Pick the MIME type used for the allowlist decision.

        A non-empty read MIME wins. Several different read MIME types
        fail closed as ``conflicting`` rather than falling back to the
        list advertisement.
        """
        normalized: List[str] = []
        for raw in read_mimes:
            mime = cls._normalize_mime_type(raw)
            if mime and mime not in normalized:
                normalized.append(mime)
        if len(normalized) > 1:
            return "conflicting"
        if normalized:
            return normalized[0]
        listed = cls._normalize_mime_type(list_mime_type)
        return listed or "unknown"

    @staticmethod
    def _combine_prompt_analysis_text(
        description: str, prompt_messages_text: str
    ) -> str:
        """Merge list metadata and rendered message bodies for content analyzers."""
        parts: List[str] = []
        if description and description.strip():
            parts.append(description.strip())
        if prompt_messages_text and prompt_messages_text.strip():
            parts.append(prompt_messages_text.strip())
        return "\n\n".join(parts)

    @staticmethod
    def _build_prompt_description_for_meta(
        result: PromptScanResult, budget: int = 8000
    ) -> str:
        """Synthesize prompt context for meta-analysis (description + message bodies)."""
        description = (getattr(result, "prompt_description", "") or "").strip()
        text = (getattr(result, "prompt_messages_text", "") or "").strip()
        if not description and not text:
            return "N/A"
        combined = Scanner._combine_prompt_analysis_text(description, text)
        if len(combined) <= budget:
            return combined
        elided = len(combined) - budget
        return (
            combined[:budget] + f"... [prompt context truncated, {elided} bytes elided]"
        )

    @staticmethod
    def _build_resource_description_for_meta(
        result: ResourceScanResult, budget: int = 8000
    ) -> str:
        """Synthesize a description string for the meta-analyzer entity context.

        Combines the MCP-advertised description (if any) with a budgeted
        snippet of the actual analyzed content. Without this, the
        meta-analyzer is asked to second-guess resource findings blind —
        it sees only ``name + uri + mime_type``. P0-3 fix.

        Args:
            result: The ResourceScanResult to summarize.
            budget: Combined character cap for description + content. Default
                ~8 KB stays well inside any modern LLM's per-call budget while
                preserving enough context for FP triage.

        Returns:
            A string of the form ``"<description>\\n\\n--- Content (first N chars) ---\\n<text>[truncated, X bytes]"``.
            Returns ``"N/A"`` if both description and text are empty.
        """
        description = (getattr(result, "resource_description", "") or "").strip()
        text = (getattr(result, "resource_text", "") or "").strip()

        if not description and not text:
            return "N/A"

        # Reserve up to half the budget for the description; in practice the
        # description is short (≤500 chars) so almost all of the budget
        # ends up available for content.
        desc_budget = min(len(description), budget // 2) if description else 0
        # Need a minimum of 256 chars of content to be meaningful for FP
        # triage; if the budget can't accommodate that after description,
        # we shrink the description rather than emit useless content.
        text_budget = max(budget - desc_budget, 256) if text else 0

        parts = []
        if description:
            if len(description) > desc_budget:
                parts.append(
                    description[:desc_budget]
                    + f"... [description truncated, {len(description) - desc_budget} bytes elided]"
                )
            else:
                parts.append(description)

        if text:
            text_total = len(text)
            if text_total > text_budget:
                snippet = (
                    text[:text_budget]
                    + f"... [content truncated, {text_total - text_budget} bytes elided]"
                )
            else:
                snippet = text
            parts.append(
                f"--- Content (first {min(text_total, text_budget)} chars) ---\n{snippet}"
            )

        return "\n\n".join(parts)

    @asynccontextmanager
    async def _item_budget_scope(self):
        """Start an item deadline, or keep the one already in scope.

        Nested calls share the outer deadline so meta uses whatever time
        the analyzers left. ``0`` disables the deadline.
        """
        token = None
        if _item_budget_var.get() is None:
            token = _item_budget_var.set(_ItemBudget())
        try:
            yield
        finally:
            if token is not None:
                _item_budget_var.reset(token)

    async def _analyze_and_meta_item(
        self,
        sem: Optional[asyncio.Semaphore],
        analyze: Callable[[], Awaitable[Any]],
        finish_meta: Optional[Callable[[Any], Awaitable[Any]]] = None,
    ) -> Any:
        """Analyze one item, then its meta pass, under one deadline.

        The scan slot is taken before the deadline starts, so queue time
        does not consume it. The slot is released before meta.
        """
        if sem is not None:
            await sem.acquire()
        try:
            async with self._item_budget_scope():
                try:
                    result = await analyze()
                finally:
                    if sem is not None:
                        sem.release()
                        sem = None
                if finish_meta is not None:
                    result = await finish_meta(result)
                return result
        finally:
            if sem is not None:
                sem.release()

    # Threat analysis, the readiness judge, and meta each make provider
    # calls. Prompt defense and OPA stay on the item deadline. The item
    # grants this allowance once, to the first of these calls.
    _OWN_TIMEOUT_LABELS = frozenset({"LLM", "META", "READINESS"})

    def _llm_call_allowance(self) -> float:
        """Seconds for one threat call, including empty-reply follow-ups.

        The first provider request can use every transport attempt and
        still return an empty body. Each later empty reply is one more
        call. A hang raises from the first request and does not reach
        those follow-ups, so this is a cap rather than time that is always
        spent. The item grants it once.
        """
        from mcpscanner.utils.analyzer_errors import compute_backoff_delay

        config = getattr(self, "_config", None)
        if config is None:
            timeout = float(MCPScannerConstants.DEFAULT_LLM_TIMEOUT)
            retries = int(MCPScannerConstants.LLM_MAX_RETRIES)
            delay = float(MCPScannerConstants.LLM_RETRY_BASE_DELAY)
        else:
            timeout = max(0.0, float(config.llm_timeout or 0))
            retries = max(0, int(config.llm_max_retries or 0))
            delay = max(0.0, float(config.llm_rate_limit_delay or 0))
        backoff = sum(compute_backoff_delay(index, delay) for index in range(retries))
        transport = (retries + 1) * timeout + backoff
        followups = retries * timeout + retries * delay
        return transport + followups

    def _mark_meta_incomplete(self, result: Any, error: Exception) -> Any:
        """Record a meta failure on the result instead of leaving it completed."""
        self._record_analyzer_error(result.analyzer_errors, "META", "meta", error)
        result.meta_filtered_findings = []
        if result.status == "completed":
            result.status = "partial" if result.analyzers else "failed"
        return result

    def _reject_failed_meta(self, result: Any, meta_result: Any) -> Optional[Any]:
        """Mark the scan incomplete when meta kept the findings but did not run.

        The meta analyzer returns a result instead of raising, so an empty
        false-positive list is not enough to tell a finished pass from a
        provider or parse failure.
        """
        failure = getattr(meta_result, "failure", None)
        if isinstance(failure, Exception):
            return self._mark_meta_incomplete(result, failure)
        return None

    async def _acquire_within_item_budget(self, sem: asyncio.Semaphore) -> bool:
        """Take a meta slot. Time spent waiting does not use the item deadline."""
        budget = _item_budget_var.get()
        if budget is None or budget.remaining() is None:
            await sem.acquire()
            return True
        if budget.remaining() <= 0:
            return False
        budget.pause()
        try:
            await sem.acquire()
        finally:
            budget.resume()
        if budget.remaining() <= 0:
            sem.release()
            return False
        return True

    @asynccontextmanager
    async def _meta_slot(self, sem: asyncio.Semaphore):
        """Hold a meta slot. Yields False when the item budget is already spent."""
        acquired = await self._acquire_within_item_budget(sem)
        if not acquired:
            yield False
            return
        try:
            yield True
        finally:
            sem.release()

    async def _wait_for_item(self, awaitable: Any, label: str) -> Any:
        """Wait for one analyzer call using the active item deadline.

        With no active budget, this call gets its own deadline. ``0``
        waits without a limit. A call that would start after the budget
        is already spent is closed and not run. LLM and meta calls are
        not cancelled before their own client retry budget.
        """
        budget = _item_budget_var.get()
        if budget is None:
            budget = _ItemBudget()
        allowance = (
            self._llm_call_allowance() if label in self._OWN_TIMEOUT_LABELS else 0.0
        )
        limit = budget.wait_limit(allowance)
        if limit is None:
            return await awaitable
        if limit <= 0:
            _discard_awaitable(awaitable)
            logger.error("%s exceeded the %gs item deadline", label, budget.limit)
            raise asyncio.TimeoutError()
        task = asyncio.ensure_future(awaitable)
        timed_out = False
        started = time.monotonic()
        paused_for = 0.0
        pause_mark: Optional[float] = None
        try:
            while not task.done():
                now = time.monotonic()
                if budget.paused:
                    # Queue time for a shared slot is not part of this grant.
                    if pause_mark is None:
                        pause_mark = now
                    await asyncio.wait({task}, timeout=0.05)
                    continue
                if pause_mark is not None:
                    paused_for += now - pause_mark
                    pause_mark = None
                elapsed = now - started - paused_for
                if elapsed >= limit:
                    timed_out = True
                    break
                await asyncio.wait({task}, timeout=max(0.0, limit - elapsed))
            if timed_out or not task.done():
                logger.error("%s exceeded the %gs item deadline", label, budget.limit)
                raise asyncio.TimeoutError()
            return task.result()
        finally:
            if not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    def _refill_prefetch(self, schedule: Callable[[], None], keep_going: bool) -> None:
        """Start the next prefetch after an item settles.

        Prompt fetches and resource reads share this call. A terminal
        result still has to refill the window, or later items are reported
        as budget-exhausted without being read.
        """
        if keep_going:
            schedule()

    def _remote_scan_limit(self) -> int:
        """How many items of one capability type may be in flight on a scan."""
        try:
            limit = int(MCPScannerConstants.REMOTE_SCAN_CONCURRENCY)
        except (TypeError, ValueError):
            limit = 8
        return max(1, limit)

    async def _await_mcp_rpc(
        self,
        awaitable: Any,
        operation: str,
        target: str,
        timeout: Optional[float] = None,
    ) -> Any:
        """Bound a list or other session RPC that previously had no timeout.

        Remote lists use ``MCP_LIST_TIMEOUT_SECONDS``. Stdio lists pass the
        server's stdio timeout so a slow local process is not cut off at 30s.
        """
        if timeout is None:
            timeout = float(MCPScannerConstants.MCP_LIST_TIMEOUT_SECONDS)
        else:
            timeout = float(timeout)
        try:
            return await asyncio.wait_for(awaitable, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise MCPConnectionError(
                f"Timed out during {operation} for MCP server at {target} "
                f"after {timeout:g}s."
            ) from exc

    async def _list_mcp_items(
        self,
        session: ClientSession,
        kind: str,
        target: str,
        timeout: Optional[float] = None,
        stop_when: Optional[Callable[[Any], bool]] = None,
    ) -> Tuple[List[Any], Optional[str]]:
        """Follow a paginated list until the cursor is exhausted.

        ``kind`` is ``tools``, ``prompts``, or ``resources``. One timeout
        covers every page. The return value is ``(items, gap)``. ``gap``
        is a fixed reason when the catalog stopped early, and ``None``
        when the cursor was exhausted. A first page that fails still
        raises. Later pages keep the items already read.
        """
        methods = {
            "tools": (session.list_tools, "tools", "tools/list"),
            "prompts": (session.list_prompts, "prompts", "prompts/list"),
            "resources": (session.list_resources, "resources", "resources/list"),
        }
        method, attr, operation = methods[kind]
        items: List[Any] = []
        cursor: Optional[str] = None
        seen: set = set()
        try:
            page_limit = int(MCPScannerConstants.MCP_LIST_PAGE_LIMIT)
        except (TypeError, ValueError):
            page_limit = 100
        page_limit = max(1, page_limit)
        if timeout is None:
            budget = float(MCPScannerConstants.MCP_LIST_TIMEOUT_SECONDS)
        else:
            budget = float(timeout)
        deadline = time.monotonic() + budget

        def unfinished(reason: str) -> Tuple[List[Any], str]:
            if not items:
                raise MCPConnectionError(
                    f"{operation} did not finish for MCP server at {target}: "
                    f"{reason}."
                )
            return items, reason

        for _page in range(page_limit):
            # The first page is given the whole budget so a caller-supplied
            # timeout is the value passed through. Later pages use only
            # what that budget has left.
            remaining = budget if cursor is None else deadline - time.monotonic()
            if remaining <= 0:
                return unfinished("the list deadline was reached")
            call = (
                method()
                if cursor is None
                else method(params=PaginatedRequestParams(cursor=cursor))
            )
            try:
                page = await self._await_mcp_rpc(
                    call, operation, target, timeout=remaining
                )
            except MCPConnectionError:
                if not items:
                    raise
                return items, "the list deadline was reached"
            except Exception:
                # A later page can fail with a transport or validation error
                # that is not an MCP protocol error. Keep the pages already
                # read. The first page still raises.
                if not items:
                    raise
                return items, "a later list page failed"
            items.extend(list(getattr(page, attr) or []))
            if stop_when is not None and any(stop_when(item) for item in items):
                return items, None
            next_cursor = getattr(page, "next_cursor", None)
            if not isinstance(next_cursor, str) or not next_cursor:
                return items, None
            if next_cursor in seen:
                return unfinished("a pagination cursor was repeated")
            seen.add(next_cursor)
            cursor = next_cursor
        return unfinished("the page limit was reached")

    def _append_list_gap(self, results: List[Any], kind: str, reason: str) -> List[Any]:
        """Keep finished items and add one incomplete result for the list."""
        message = f"MCP {kind} list did not finish: {reason}."
        finding = SecurityFinding(
            severity="INFO",
            summary=message,
            analyzer="MCP",
            threat_category="ANALYZER INFRASTRUCTURE",
            details={"error_type": "ListCoverageError", "error": reason},
        )
        # The same fixed reason is an analyzer error so API and report
        # filters keep it when they only retain error entries.
        error = {
            "analyzer": "MCP",
            "content_type": f"{kind}_list",
            "message": message,
        }
        if kind == "tools":
            results.append(
                ToolScanResult(
                    tool_name="(tools/list)",
                    tool_description="",
                    status="failed",
                    analyzers=[],
                    findings=[finding],
                    analyzer_errors=[error],
                )
            )
        elif kind == "prompts":
            results.append(
                PromptScanResult(
                    prompt_name="(prompts/list)",
                    prompt_description="",
                    status="failed",
                    analyzers=[],
                    findings=[finding],
                    analyzer_errors=[error],
                )
            )
        else:
            results.append(
                ResourceScanResult(
                    resource_uri="(resources/list)",
                    resource_name="(resources/list)",
                    resource_mime_type="unknown",
                    status="failed",
                    analyzers=[],
                    findings=[finding],
                    analyzer_errors=[error],
                )
            )
        return results

    def _missing_listed_item(self, found: Any, gap: Optional[str], message: str) -> Any:
        """Return ``found``, or fail without claiming the catalog is complete."""
        if found is not None:
            return found
        if gap:
            raise MCPConnectionError(
                f"The capability list did not finish ({gap}), so this item "
                "cannot be reported missing."
            )
        raise ValueError(message)

    async def _analyze_tool_for_scan(
        self,
        tool: MCPTool,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict],
        scan_sem: asyncio.Semaphore,
        meta_sem: asyncio.Semaphore,
    ) -> ToolScanResult:
        """Analyze one tool, then its meta pass, under the scan limits."""

        async def analyze() -> ToolScanResult:
            return await self._analyze_tool(tool, analyzers, http_headers)

        async def meta(result: ToolScanResult) -> ToolScanResult:
            return await self._meta_analyze_one_tool(result, meta_sem)

        use_meta = AnalyzerEnum.META in analyzers and self._meta_analyzer is not None
        return await self._analyze_and_meta_item(
            scan_sem, analyze, meta if use_meta else None
        )

    async def _analyze_tools_bounded(
        self,
        tools: Sequence[MCPTool],
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> List[ToolScanResult]:
        """Analyze tools with a concurrency cap. Meta runs as each tool finishes."""
        scan_sem = asyncio.Semaphore(self._remote_scan_limit())
        meta_sem = asyncio.Semaphore(self._META_CONCURRENCY)
        return list(
            await asyncio.gather(
                *(
                    self._analyze_tool_for_scan(
                        tool, analyzers, http_headers, scan_sem, meta_sem
                    )
                    for tool in tools
                )
            )
        )

    # P1-2: cap concurrent LLM round-trips during meta-analysis. With this
    # cap a 30-tool server completes in ~30/8 ≈ 4 sequential waves instead
    # of 30 sequential round-trips, while staying well within typical Bedrock
    # / Azure OpenAI rate-limit budgets. Operators with stricter per-tenant
    # limits can monkey-patch ``Scanner._META_CONCURRENCY`` or subclass.
    _META_CONCURRENCY = 8

    def _skip_meta_for_infrastructure(self, result: Any) -> bool:
        """True when meta cannot change this result.

        An empty finding list, or a list that is only analyzer
        infrastructure, is kept as-is. Those calls would only take a meta
        slot and an LLM slot to return the same findings.
        """
        findings = getattr(result, "findings", None) or []
        if findings and any(
            getattr(finding, "threat_category", None) != "ANALYZER INFRASTRUCTURE"
            for finding in findings
        ):
            return False
        result.meta_filtered_findings = []
        return True

    async def _meta_analyze_one_tool(
        self,
        result: ToolScanResult,
        sem: "asyncio.Semaphore",
    ) -> ToolScanResult:
        """Per-tool meta-analysis worker. Bounded by ``sem``."""
        if self._skip_meta_for_infrastructure(result):
            return result

        entity_context = {
            "type": "tool",
            "name": result.tool_name,
            "description": result.tool_description,
        }
        tool_analyzers = list({f.analyzer for f in result.findings})

        async with self._meta_slot(sem) as acquired:
            if not acquired:
                return self._mark_meta_incomplete(result, asyncio.TimeoutError())
            try:
                meta_result = await self._wait_for_item(
                    self._meta_analyzer.analyze_findings(
                        findings=result.findings,
                        analyzers_used=tool_analyzers,
                        entity_context=entity_context,
                    ),
                    "META",
                )
                rejected = self._reject_failed_meta(result, meta_result)
                if rejected is not None:
                    return rejected
                kept, dropped = apply_meta_analysis(result.findings, meta_result)
                enriched = ToolScanResult(
                    tool_name=result.tool_name,
                    tool_description=result.tool_description,
                    status=result.status,
                    analyzers=result.analyzers,
                    findings=kept,
                    server_source=result.server_source,
                    server_name=result.server_name,
                    analyzer_errors=result.analyzer_errors,
                )
                enriched.meta_filtered_findings = dropped
                return enriched
            except Exception as e:
                logger.error("Meta-analysis failed for tool: %s", type(e).__name__)
                # P2-2: same reset on the failure path. Returning the
                # original with stale ``meta_filtered_findings`` would
                # claim findings were filtered when meta in fact errored.
                return self._mark_meta_incomplete(result, e)

    async def _meta_analyze_one_prompt(
        self,
        result: PromptScanResult,
        sem: "asyncio.Semaphore",
    ) -> PromptScanResult:
        """Per-prompt meta-analysis worker. Bounded by ``sem``."""
        if self._skip_meta_for_infrastructure(result):
            return result

        entity_context = {
            "type": "prompt",
            "name": result.prompt_name,
            "description": self._build_prompt_description_for_meta(result),
        }
        prompt_analyzers = list({f.analyzer for f in result.findings})

        async with self._meta_slot(sem) as acquired:
            if not acquired:
                return self._mark_meta_incomplete(result, asyncio.TimeoutError())
            try:
                meta_result = await self._wait_for_item(
                    self._meta_analyzer.analyze_findings(
                        findings=result.findings,
                        analyzers_used=prompt_analyzers,
                        entity_context=entity_context,
                    ),
                    "META",
                )
                rejected = self._reject_failed_meta(result, meta_result)
                if rejected is not None:
                    return rejected
                kept, dropped = apply_meta_analysis(result.findings, meta_result)
                enriched = PromptScanResult(
                    prompt_name=result.prompt_name,
                    prompt_description=result.prompt_description,
                    status=result.status,
                    analyzers=result.analyzers,
                    findings=kept,
                    server_source=result.server_source,
                    server_name=result.server_name,
                    prompt_messages_text=getattr(result, "prompt_messages_text", "")
                    or "",
                    analyzer_errors=result.analyzer_errors,
                )
                enriched.meta_filtered_findings = dropped
                return enriched
            except Exception as e:
                logger.error("Meta-analysis failed for prompt: %s", type(e).__name__)
                return self._mark_meta_incomplete(result, e)

    async def _meta_analyze_one_resource(
        self,
        result: ResourceScanResult,
        sem: "asyncio.Semaphore",
    ) -> ResourceScanResult:
        """Per-resource meta-analysis worker. Bounded by ``sem``."""
        if self._skip_meta_for_infrastructure(result):
            return result

        # P0-3 fix: pipe MCP description + analyzed text content to the
        # meta-analyzer. Previously the meta-analyzer was asked to FP-filter
        # resource findings with only name/uri/mime_type for context,
        # making FP filtering on resources essentially unsupervised.
        entity_context = {
            "type": "resource",
            "name": result.resource_name,
            "uri": result.resource_uri,
            "mime_type": result.resource_mime_type,
            "description": self._build_resource_description_for_meta(result),
        }
        res_analyzers = list({f.analyzer for f in result.findings})

        async with self._meta_slot(sem) as acquired:
            if not acquired:
                return self._mark_meta_incomplete(result, asyncio.TimeoutError())
            try:
                meta_result = await self._wait_for_item(
                    self._meta_analyzer.analyze_findings(
                        findings=result.findings,
                        analyzers_used=res_analyzers,
                        entity_context=entity_context,
                    ),
                    "META",
                )
                rejected = self._reject_failed_meta(result, meta_result)
                if rejected is not None:
                    return rejected
                kept, dropped = apply_meta_analysis(result.findings, meta_result)
                enriched = ResourceScanResult(
                    resource_uri=result.resource_uri,
                    resource_name=result.resource_name,
                    resource_mime_type=result.resource_mime_type,
                    status=result.status,
                    analyzers=result.analyzers,
                    findings=kept,
                    server_source=result.server_source,
                    server_name=result.server_name,
                    analyzer_errors=result.analyzer_errors,
                    # P0-3 carry-through: preserve the description and text
                    # the primary analyzers consumed. Without this, every
                    # ``--enable-meta`` (or API ``enable_meta=True``) run
                    # silently zeroed those fields on the post-meta result,
                    # defeating the contract that ResourceScanResult holds
                    # the evidence the analyzers saw.
                    resource_description=getattr(result, "resource_description", "")
                    or "",
                    resource_text=getattr(result, "resource_text", "") or "",
                )
                enriched.meta_filtered_findings = dropped
                return enriched
            except Exception as e:
                logger.error("Meta-analysis failed for resource: %s", type(e).__name__)
                return self._mark_meta_incomplete(result, e)

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

        Public, single-source-of-truth entrypoint that the static-config
        CLI path uses (P1-6). Previously the CLI reimplemented the entire
        per-result loop inline in ``cli.py``; that duplicate had already
        drifted from the Scanner's own helpers and produced two real bugs
        (P0-4: silently dropped resource/instructions enrichment,
        P0-5: silently no-op'd on the IAM-only Bedrock flow). Routing the
        CLI through this method keeps all four entity types (tool, prompt,
        resource, instructions) in lock-step.

        Args:
            scan_results: Heterogeneous list of ScanResult subclasses.
            analyzers: Analyzer set requested for the scan. If META is not
                in this list (or omitted) the input is returned unchanged.
                Default: ``[META]`` so callers that already gated on
                ``--enable-meta`` upstream don't need to re-pass it.

        Returns:
            The same list with ``ScanResult.meta_filtered_findings``
            populated on each enriched result. Order is preserved. On
            per-result failure the original is kept (no silent drop).
        """
        if analyzers is None:
            analyzers = [AnalyzerEnum.META]
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return list(scan_results)

        sem = asyncio.Semaphore(self._META_CONCURRENCY)

        async def _dispatch(result: ScanResult) -> ScanResult:
            if isinstance(result, ToolScanResult):
                return await self._meta_analyze_one_tool(result, sem)
            if isinstance(result, PromptScanResult):
                return await self._meta_analyze_one_prompt(result, sem)
            if isinstance(result, ResourceScanResult):
                return await self._meta_analyze_one_resource(result, sem)
            if isinstance(result, InstructionsScanResult):
                # No bulk endpoint takes a list of instructions, but the CLI
                # static path may include one in ``all_results``. Re-use the
                # single-result helper so behaviour stays in lock-step.
                return await self._run_meta_analysis_on_instructions_result(
                    result, analyzers
                )
            # Unknown result subclass: don't silently drop — pass through.
            return result

        return list(await asyncio.gather(*(_dispatch(r) for r in scan_results)))

    async def _run_meta_analysis_on_results(
        self,
        scan_results: List[ToolScanResult],
        analyzers: List[AnalyzerEnum],
    ) -> List[ToolScanResult]:
        """Run meta-analysis on tool scan results if META analyzer is enabled.

        P1-2: bounded concurrency. Previously this loop awaited each
        per-tool LLM call sequentially, making total wall-clock cost
        N × LLM round-trip (~1–4 s each). Now we run up to
        ``_META_CONCURRENCY`` analyses in flight simultaneously, with
        ``asyncio.gather`` preserving the input order so consumers don't
        see reshuffled findings.

        Args:
            scan_results: The tool scan results from primary analyzers.
            analyzers: The list of analyzers that were used.

        Returns:
            The scan results with meta-analysis enrichments applied,
            in the same order as ``scan_results``.
        """
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return scan_results

        sem = asyncio.Semaphore(self._META_CONCURRENCY)
        return list(
            await asyncio.gather(
                *(self._meta_analyze_one_tool(r, sem) for r in scan_results)
            )
        )

    async def _run_meta_analysis_on_prompt_results(
        self,
        scan_results: List[PromptScanResult],
        analyzers: List[AnalyzerEnum],
    ) -> List[PromptScanResult]:
        """Run meta-analysis on prompt scan results, bounded by _META_CONCURRENCY."""
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return scan_results

        sem = asyncio.Semaphore(self._META_CONCURRENCY)
        return list(
            await asyncio.gather(
                *(self._meta_analyze_one_prompt(r, sem) for r in scan_results)
            )
        )

    async def _run_meta_analysis_on_resource_results(
        self,
        scan_results: List[ResourceScanResult],
        analyzers: List[AnalyzerEnum],
    ) -> List[ResourceScanResult]:
        """Run meta-analysis on resource scan results, bounded by _META_CONCURRENCY."""
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            return scan_results

        sem = asyncio.Semaphore(self._META_CONCURRENCY)
        return list(
            await asyncio.gather(
                *(self._meta_analyze_one_resource(r, sem) for r in scan_results)
            )
        )

    async def _run_meta_analysis_on_instructions_result(
        self,
        result: InstructionsScanResult,
        analyzers: List[AnalyzerEnum],
    ) -> InstructionsScanResult:
        """Run meta-analysis on instructions scan result if META analyzer is enabled.

        H1 follow-up: parity with the other three ``_meta_analyze_one_*``
        helpers — every early-return / exception path resets
        ``meta_filtered_findings`` so a re-invocation cannot leak a prior
        run's audit list into the new response. Without this the
        instructions helper alone would report stale filtering
        (asymmetric with tools/prompts/resources, which the P2-2 fix
        already covers).
        """
        if AnalyzerEnum.META not in analyzers or self._meta_analyzer is None:
            result.meta_filtered_findings = []
            return result

        if not result.findings:
            result.meta_filtered_findings = []
            return result

        # M3 follow-up: mirror P0-3's resource-context fix. The previous
        # ``[:500]`` truncation made the meta-analyzer second-guess
        # findings against ~500 bytes of evidence; if a finding cited
        # text past byte 500 the LLM couldn't see it and FP filtering
        # devolved into "trust whatever the LLM hallucinates from the
        # opening paragraph". Use the same budgeted-snippet helper as
        # resources so instructions get the full context window the
        # primary analyzers consumed.
        entity_context = {
            "type": "instructions",
            "name": result.server_name,
            "description": self._build_instructions_description_for_meta(result),
        }
        instr_analyzers = list({f.analyzer for f in result.findings})

        try:
            meta_result = await self._wait_for_item(
                self._meta_analyzer.analyze_findings(
                    findings=result.findings,
                    analyzers_used=instr_analyzers,
                    entity_context=entity_context,
                ),
                "META",
            )
            rejected = self._reject_failed_meta(result, meta_result)
            if rejected is not None:
                return rejected
            kept, dropped = apply_meta_analysis(result.findings, meta_result)
            enriched_result = InstructionsScanResult(
                instructions=result.instructions,
                server_name=result.server_name,
                protocol_version=result.protocol_version,
                status=result.status,
                analyzers=result.analyzers,
                findings=kept,
                server_source=result.server_source,
                analyzer_errors=result.analyzer_errors,
            )
            enriched_result.meta_filtered_findings = dropped
            return enriched_result
        except Exception as e:
            logger.error("Meta-analysis failed for instructions: %s", type(e).__name__)
            return self._mark_meta_incomplete(result, e)

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
        """Return True when the server reports a capability is unavailable.

        Covers three real-world shapes of "this method isn't implemented":

        1. Spec-compliant JSON-RPC ``-32601`` ("Method not found").
        2. Free-form message tokens (some servers return ``-32603`` with a
           ``"unsupported"``-style message).
        3. The MCP Python SDK's synthetic ``32600`` + ``"Session terminated"``
           that ``mcp/client/streamable_http.py`` emits when the server
           replies to a JSON-RPC POST with a plain HTTP 404. Many real-world
           MCP servers (BigQuery, several Google APIs, some Cloudflare/GitHub
           endpoints) return 404 for unimplemented ``resources/list`` or
           ``prompts/list`` instead of a proper ``-32601`` error, and the SDK
           relabels that as a session-terminated error. Treat the synthetic
           shape as a missing-capability signal so callers can return ``[]``
           instead of bubbling a misleading 500.
        """
        messages = [str(error)]
        code = getattr(error, "code", None)

        rpc_error = getattr(error, "error", None)
        if hasattr(rpc_error, "code") and getattr(rpc_error, "code") is not None:
            code = code or rpc_error.code
            rpc_message = getattr(rpc_error, "message", None)
            if rpc_message:
                messages.append(str(rpc_message))
        elif isinstance(rpc_error, dict):
            code = code or rpc_error.get("code")
            rpc_message = rpc_error.get("message")
            if rpc_message:
                messages.append(str(rpc_message))

        combined_message = " ".join(m for m in messages if m).lower()

        if code == -32601:
            return True

        # SDK-synthetic shape for "server returned HTTP 404 for this method".
        # We require BOTH the code and the canonical message so we don't
        # silently swallow real mid-session terminations (which can use the
        # same 32600 code with different messages).
        if code == 32600 and "session terminated" in combined_message:
            return True

        tokens = (
            "method not found",
            "methodnotfound",
            "not implemented",
            "unsupported",
            "does not have",
            "doesn't have",
        )
        return any(token in combined_message for token in tokens)

    @staticmethod
    def _should_fallback_to_initialize(
        error: Exception, *, legacy_stdio: bool = False, legacy_http: bool = False
    ) -> bool:
        """Return True when ``discover()`` failed in a way that ``initialize()`` may still work."""
        rpc_error = getattr(error, "error", None)
        code = getattr(error, "code", None)
        if code is None:
            code = getattr(rpc_error, "code", None)
        # MCP 1.x streamable HTTP servers can reject pre-initialize discover
        # with this exact missing-session response. It is safe to retry the
        # legacy initialize handshake only for this known server shape.
        if code == -32600:
            return (
                legacy_http
                and getattr(rpc_error, "message", str(error))
                == "Bad Request: Missing session ID"
                and getattr(rpc_error, "data", None) in (None, "")
            )
        # MCP 1.x Python stdio servers use this exact generic error for an
        # unknown discover method. A modern server may use -32602 for a real
        # payload defect, so do not infer legacy support from the code alone.
        if code == -32602:
            return (
                legacy_stdio
                and getattr(rpc_error, "message", str(error))
                == "Invalid request parameters"
                and getattr(rpc_error, "data", None) in (None, "")
            )
        return (
            code == UNSUPPORTED_PROTOCOL_VERSION
            or Scanner._is_missing_capability_error(error)
        )

    @staticmethod
    def _server_supports_capability(session: Any, capability: str) -> Optional[bool]:
        """Check whether the server advertised support for a capability.

        Prefers ``ClientSession.server_capabilities`` (mcp ≥ 2.0, works for
        both ``initialize()`` and ``discover()``). Falls back to the stashed
        connect result on ``session._init_result`` for older call paths.

        Returns:

        * ``True``  — server explicitly advertised this capability.
        * ``False`` — server explicitly omitted it; we can short-circuit.
        * ``None``  — we don't have init info; caller must fall back to the
                     try/except path on the actual JSON-RPC call.
        """
        capabilities = None
        init_result = getattr(session, "_init_result", None)
        if init_result is not None:
            capabilities = getattr(init_result, "capabilities", None)
        elif getattr(session, "protocol_version", None) is not None:
            capabilities = getattr(session, "server_capabilities", None)
        if capabilities is None:
            return None
        # ServerCapabilities is a pydantic model; missing optional fields
        # default to None. A non-None object (even if empty) signals the
        # server advertised the capability.
        return getattr(capabilities, capability, None) is not None

    async def _negotiate_mcp_session(
        self,
        session: ClientSession,
        *,
        legacy_stdio: bool = False,
        legacy_http: bool = False,
    ) -> Any:
        """Negotiate protocol version with the server.

        On mcp ≥ 2.0, tries modern ``server/discover`` first (``2026-07-28``)
        for all transports (streamable HTTP, SSE where applicable, and stdio).
        Falls back to legacy ``initialize()`` when discover is unavailable or
        the server only speaks handshake-era protocol versions. On mcp 1.x
        (no ``discover`` method), uses ``initialize()`` directly.
        """
        if hasattr(session, "discover"):
            try:
                connect_result = await session.discover()
                session._init_result = connect_result
                logger.debug(
                    'MCP session negotiated via discover: protocol="%s"',
                    session.protocol_version,
                )
                return connect_result
            except McpError as e:
                if not self._should_fallback_to_initialize(
                    e, legacy_stdio=legacy_stdio, legacy_http=legacy_http
                ):
                    raise
                if getattr(e, "code", None) == -32602:
                    logger.warning(
                        "Legacy-shaped server/discover rejection over stdio; "
                        "trying initialize() after: %s",
                        e,
                    )
                elif getattr(e, "code", None) == -32600:
                    logger.warning(
                        "Legacy-shaped server/discover rejection over HTTP; "
                        "trying initialize() after: %s",
                        e,
                    )
                logger.debug(
                    "server/discover unavailable (%s), falling back to initialize()",
                    e,
                )

        connect_result = await session.initialize()
        session._init_result = connect_result
        protocol_version = getattr(
            connect_result,
            "protocol_version",
            getattr(connect_result, "protocolVersion", "unknown"),
        )
        logger.debug(
            'MCP session negotiated via initialize: protocol="%s"',
            protocol_version,
        )
        return connect_result

    @staticmethod
    def _session_connect_metadata(session: Any) -> tuple[Any, Any, Optional[str]]:
        """Return ``(instructions, server_info, protocol_version)`` from a session."""
        init_result = getattr(session, "_init_result", None)
        if init_result is not None:
            instructions = getattr(init_result, "instructions", None)
            server_info = getattr(init_result, "serverInfo", None)
            if server_info is None:
                server_info = getattr(init_result, "server_info", None)
            protocol_version = getattr(init_result, "protocolVersion", None)
            if protocol_version is None:
                protocol_version = getattr(init_result, "protocol_version", None)
            # DiscoverResult keeps identity and the negotiated version on the
            # session, while instructions are present on the result.
            if not hasattr(init_result, "instructions"):
                instructions = getattr(session, "instructions", None)
            if server_info is None:
                server_info = getattr(session, "server_info", None)
            if protocol_version is None:
                protocol_version = getattr(session, "protocol_version", None)
            return instructions, server_info, protocol_version

        return (
            getattr(session, "instructions", None),
            getattr(session, "server_info", None),
            getattr(session, "protocol_version", None),
        )

    @staticmethod
    def _analyzer_label(analyzer: Any) -> str:
        """Return a stable display name for enum and custom analyzers."""
        return str(getattr(analyzer, "value", analyzer))

    @classmethod
    def _analysis_outcome(
        cls,
        successful_analyzers: List[AnalyzerEnum],
        custom_analyzers: List[str],
        analyzer_errors: List[Dict[str, str]],
    ) -> Tuple[List[Any], str]:
        """Return analyzers with successful invocations and scan status.

        A multi-part analyzer remains listed when one part succeeds and
        another fails; the errors and partial status describe the gap.
        """
        succeeded = []
        seen = set()
        for analyzer in [*successful_analyzers, *custom_analyzers]:
            label = cls._analyzer_label(analyzer).casefold()
            if label not in seen:
                succeeded.append(analyzer)
                seen.add(label)
        if not analyzer_errors:
            return succeeded, "completed" if succeeded else "skipped"
        return succeeded, "partial" if succeeded else "failed"

    @staticmethod
    def _record_infrastructure_gaps(
        findings: List[Any],
        analyzer_errors: List[Dict[str, str]],
        content_type: str,
    ) -> None:
        """Record an analyzer error for each infrastructure finding.

        The finding stays on the result. The error keeps status from
        staying ``completed`` when an analyzer returned a failure as a
        finding instead of raising.
        """
        seen = {
            (error.get("analyzer"), error.get("content_type"))
            for error in analyzer_errors
        }
        for finding in findings:
            if getattr(finding, "threat_category", None) != "ANALYZER INFRASTRUCTURE":
                continue
            label = str(getattr(finding, "analyzer", None) or "ANALYZER")
            key = (label, content_type)
            if key in seen:
                continue
            seen.add(key)
            raw_details = getattr(finding, "details", None)
            details = raw_details if isinstance(raw_details, dict) else {}
            error_type = details.get("error_type")
            if not isinstance(error_type, str) or not error_type.isidentifier():
                error_type = "AnalyzerInfrastructureError"
            analyzer_errors.append(
                {
                    "analyzer": label,
                    "content_type": content_type,
                    "message": f"{error_type} during analysis",
                }
            )

    @staticmethod
    def _record_analyzer_error(
        analyzer_errors: List[Dict[str, str]],
        analyzer: Any,
        content_type: str,
        error: Exception,
    ) -> None:
        label = Scanner._analyzer_label(analyzer)
        error_type = type(error).__name__
        analyzer_errors.append(
            {
                "analyzer": label,
                "content_type": content_type,
                # Provider exceptions can contain URLs, headers, or input.
                # Keep the public result useful without echoing those values.
                "message": f"{error_type} during analysis",
            }
        )
        logger.error("%s analysis failed on %s: %s", label, content_type, error_type)

    @staticmethod
    async def _parallel_analyzer_parts(
        parts: Sequence[Callable[[], Awaitable[Tuple[list, list, list, list]]]],
    ) -> Tuple[list, list, list, list]:
        """Run one item's analyzer parts together.

        Results are merged in part order so a fast analyzer cannot reorder
        findings ahead of an earlier part. Each part catches its own errors.
        """
        if not parts:
            return [], [], [], []
        done = await asyncio.gather(*(part() for part in parts))
        findings: list = []
        analyzers: list = []
        custom_names: list = []
        errors: list = []
        for found, ok, names, errs in done:
            findings.extend(found)
            analyzers.extend(ok)
            custom_names.extend(names)
            errors.extend(errs)
        return findings, analyzers, custom_names, errors

    @_share_item_budget
    async def _analyze_tool(
        self,
        tool: MCPTool,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> ToolScanResult:
        """Analyze a single MCP tool using specified analyzers.

        Args:
            tool (MCPTool): The MCP tool to analyze.
            analyzers (List[AnalyzerEnum]): List of analyzers to run.

        Returns:
            ScanResult: The result of the analysis.
        """
        all_findings = []
        successful_analyzers: List[AnalyzerEnum] = []
        analyzer_errors: List[Dict[str, str]] = []
        name = tool.name
        description = tool.description
        tool_json = tool.model_dump_json(by_alias=True)
        tool_data = json.loads(tool_json)

        parts = []

        if AnalyzerEnum.SCHEMA in analyzers:

            async def schema_part() -> Tuple[list, list, list, list]:
                try:
                    schema_findings = await self._wait_for_item(
                        self._schema_analyzer.analyze(
                            tool_json,
                            {"tool_name": name, "content_type": "parameters"},
                        ),
                        "SCHEMA",
                    )
                    return schema_findings, [AnalyzerEnum.SCHEMA], [], []
                except Exception as e:
                    errors: List[Dict[str, str]] = []
                    self._record_analyzer_error(errors, "SCHEMA", "parameters", e)
                    return [], [], [], errors

            parts.append(schema_part)

        if AnalyzerEnum.API in analyzers and self._api_analyzer:

            async def api_part() -> Tuple[list, list, list, list]:
                try:
                    api_findings = await self._wait_for_item(
                        self._api_analyzer.analyze(
                            description,
                            {"tool_name": name, "content_type": "description"},
                        ),
                        "API",
                    )
                    for finding in api_findings:
                        finding.analyzer = "API"
                    return api_findings, [AnalyzerEnum.API], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "API", "description", e)
                    return [], [], [], errors

            parts.append(api_part)

        if AnalyzerEnum.YARA in analyzers:

            async def yara_description_part() -> Tuple[list, list, list, list]:
                try:
                    yara_desc_findings = await self._wait_for_item(
                        self._yara_analyzer.analyze(
                            description,
                            {"tool_name": name, "content_type": "description"},
                        ),
                        "YARA",
                    )
                    for finding in yara_desc_findings:
                        finding.analyzer = "YARA"
                    return yara_desc_findings, [AnalyzerEnum.YARA], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "YARA", "description", e)
                    return [], [], [], errors

            async def yara_parameters_part() -> Tuple[list, list, list, list]:
                try:
                    # Copy before dropping the description so readiness and
                    # other parts still see the original tool text.
                    parameter_data = dict(tool_data)
                    parameter_data.pop("description", None)
                    yara_params_findings = await self._wait_for_item(
                        self._yara_analyzer.analyze(
                            json.dumps(parameter_data),
                            {"tool_name": name, "content_type": "parameters"},
                        ),
                        "YARA",
                    )
                    for finding in yara_params_findings:
                        finding.analyzer = "YARA"
                    return yara_params_findings, [AnalyzerEnum.YARA], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "YARA", "parameters", e)
                    return [], [], [], errors

            parts.append(yara_description_part)
            parts.append(yara_parameters_part)

        if AnalyzerEnum.LLM in analyzers and self._llm_analyzer:

            async def llm_part() -> Tuple[list, list, list, list]:
                try:
                    analysis_content = f"Tool Name: {name}\n"
                    analysis_content += f"Description: {description}\n"
                    if "inputSchema" in tool_data:
                        analysis_content += (
                            "Parameters Schema: "
                            f"{json.dumps(tool_data['inputSchema'], indent=2)}\n"
                        )
                    llm_findings = await self._wait_for_item(
                        self._llm_analyzer.analyze(
                            analysis_content,
                            {"tool_name": name, "content_type": "comprehensive"},
                        ),
                        "LLM",
                    )
                    for finding in llm_findings:
                        finding.analyzer = "LLM"
                    return llm_findings, [AnalyzerEnum.LLM], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "LLM", "comprehensive", e)
                    return [], [], [], errors

            parts.append(llm_part)
        elif AnalyzerEnum.LLM in analyzers and not self._llm_analyzer:
            logger.warning(
                "LLM scan requested for tool '%s' but LLM analyzer not "
                "initialized (MCP_SCANNER_LLM_API_KEY missing)",
                name,
            )

        if AnalyzerEnum.READINESS in analyzers and self._readiness_analyzer:

            async def readiness_part() -> Tuple[list, list, list, list]:
                # Heuristics, then OPA, then the judge. Those steps share
                # the incomplete-check result, so they stay in this order.
                # The part itself runs beside the other analyzers.
                readiness_context = {
                    "tool_name": name,
                    "content_type": "tool_definition",
                    "tool_definition": tool_data,
                }
                readiness = self._readiness_analyzer
                collected: List[Any] = []
                errors: List[Dict[str, str]] = []
                failed = False
                heuristics_completed = True
                failed_checks: List[str] = []
                try:
                    collected.extend(
                        readiness.heuristic_findings(tool_json, readiness_context)
                    )
                except ReadinessCheckFailure as exc:
                    collected.extend(exc.findings)
                    failed_checks = list(exc.failed_checks)
                    heuristics_completed = False
                    failed = True
                    self._record_analyzer_error(
                        errors, "READINESS", "tool_definition", exc
                    )
                    if failed_checks and errors:
                        errors[-1]["message"] = (
                            "ReadinessCheckFailure during analysis ("
                            + ", ".join(failed_checks)
                            + ")"
                        )
                except Exception as e:
                    heuristics_completed = False
                    failed = True
                    self._record_analyzer_error(
                        errors, "READINESS", "tool_definition", e
                    )
                if getattr(readiness, "opa_enabled", False):
                    try:
                        collected.extend(
                            await self._wait_for_item(
                                readiness.opa_findings(tool_json, readiness_context),
                                "OPA",
                            )
                        )
                    except Exception as e:
                        failed = True
                        self._record_analyzer_error(
                            errors, "READINESS", "tool_definition", e
                        )
                if getattr(readiness, "llm_judge_available", False):
                    try:
                        collected.extend(
                            await self._wait_for_item(
                                readiness.judge_findings(tool_json, readiness_context),
                                "READINESS",
                            )
                        )
                    except Exception as e:
                        failed = True
                        self._record_analyzer_error(
                            errors, "READINESS", "tool_definition", e
                        )
                if any(
                    getattr(finding, "threat_category", None)
                    == "ANALYZER INFRASTRUCTURE"
                    for finding in collected
                ):
                    failed = True
                if not heuristics_completed:
                    record_gap = getattr(readiness, "incomplete_check_finding", None)
                    if callable(record_gap):
                        collected.append(record_gap(name, failed_checks))
                readiness_findings = readiness.stamp_readiness(collected)
                if not heuristics_completed or failed:
                    mark_gap = getattr(readiness, "mark_checks_incomplete", None)
                    if callable(mark_gap):
                        mark_gap(readiness_findings, failed_checks)
                for finding in readiness_findings:
                    finding.analyzer = "READINESS"
                ok = (
                    [AnalyzerEnum.READINESS] if readiness_findings or not failed else []
                )
                return readiness_findings, ok, [], errors

            parts.append(readiness_part)

        if AnalyzerEnum.PROMPT_DEFENSE in analyzers and self._prompt_defense_analyzer:

            async def prompt_defense_part() -> Tuple[list, list, list, list]:
                try:
                    pd_findings = await self._wait_for_item(
                        self._prompt_defense_analyzer.analyze(
                            description,
                            {"tool_name": name, "content_type": "description"},
                        ),
                        "PROMPT_DEFENSE",
                    )
                    for finding in pd_findings:
                        finding.analyzer = "PromptDefense"
                    return pd_findings, [AnalyzerEnum.PROMPT_DEFENSE], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(
                        errors, "PROMPT_DEFENSE", "description", e
                    )
                    return [], [], [], errors

            parts.append(prompt_defense_part)

        for custom_analyzer in self._custom_analyzers:

            async def custom_part(
                analyzer=custom_analyzer,
            ) -> Tuple[list, list, list, list]:
                try:
                    custom_context = {
                        "tool_name": name,
                        "content_type": "description",
                    }
                    if http_headers:
                        custom_context["http_headers"] = http_headers
                    findings = await self._wait_for_item(
                        analyzer.analyze(description, custom_context),
                        "custom analyzer",
                    )
                    for finding in findings:
                        finding.analyzer = analyzer.name
                    return findings, [], [analyzer.name], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, analyzer.name, "description", e)
                    return [], [], [], errors

            parts.append(custom_part)

        (
            all_findings,
            successful_analyzers,
            custom_analyzer_names,
            analyzer_errors,
        ) = await self._parallel_analyzer_parts(parts)

        # Combine enum analyzers and custom analyzer names, excluding META
        # since meta-analysis enriches existing findings rather than producing
        # its own output section
        self._record_infrastructure_gaps(all_findings, analyzer_errors, "comprehensive")
        all_analyzers, status = self._analysis_outcome(
            successful_analyzers, custom_analyzer_names, analyzer_errors
        )

        return ToolScanResult(
            tool_name=name,
            tool_description=description,
            status=status,
            analyzers=all_analyzers,
            findings=all_findings,
            analyzer_errors=analyzer_errors,
        )

    @_share_item_budget
    async def _analyze_prompt(
        self,
        prompt: MCPPrompt,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
        prompt_messages_text: str = "",
    ) -> PromptScanResult:
        """Analyze a single MCP prompt using specified analyzers.

        Args:
            prompt (MCPPrompt): The MCP prompt to analyze.
            analyzers (List[AnalyzerEnum]): List of analyzers to run.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.
            prompt_messages_text (str): Rendered message bodies from ``prompts/get``.

        Returns:
            PromptScanResult: The result of the analysis.
        """
        all_findings = []
        successful_analyzers: List[AnalyzerEnum] = []
        analyzer_errors: List[Dict[str, str]] = []
        name = prompt.name
        description = prompt.description or ""
        bounded_messages, limit_error = self._apply_body_budget(
            prompt_messages_text,
            MCPScannerConstants.MAX_PROMPT_BODY_CHARS,
            MCPScannerConstants.MAX_PROMPT_RESOURCE_AGGREGATE_CHARS,
        )
        if limit_error is not None:
            return self._prompt_messages_fetch_failure_result(
                prompt, limit_error, analyzers
            )
        prompt_messages_text = bounded_messages
        combined_content = self._combine_prompt_analysis_text(
            description, prompt_messages_text
        )

        # Safely parse prompt data
        try:
            prompt_json = prompt.model_dump_json()
            prompt_data = json.loads(prompt_json)
        except (json.JSONDecodeError, AttributeError, TypeError) as e:
            logger.warning(
                f"Error parsing prompt '{name}' data: {e}. Using minimal data."
            )
            prompt_data = {"name": name, "description": description}

        parts = []
        analyzed_text = combined_content or description

        if AnalyzerEnum.API in analyzers and self._api_analyzer:

            async def api_part() -> Tuple[list, list, list, list]:
                try:
                    api_findings = await self._wait_for_item(
                        self._api_analyzer.analyze(
                            analyzed_text,
                            {"prompt_name": name, "content_type": "prompt_content"},
                        ),
                        "API",
                    )
                    for finding in api_findings:
                        finding.analyzer = "API"
                    return api_findings, [AnalyzerEnum.API], [], []
                except Exception as e:
                    errors: List[Dict[str, str]] = []
                    self._record_analyzer_error(errors, "API", "prompt_content", e)
                    return [], [], [], errors

            parts.append(api_part)

        if AnalyzerEnum.YARA in analyzers:

            async def yara_body_part() -> Tuple[list, list, list, list]:
                try:
                    yara_desc_findings = await self._wait_for_item(
                        self._yara_analyzer.analyze(
                            analyzed_text,
                            {
                                "prompt_name": name,
                                "content_type": "prompt_content",
                            },
                        ),
                        "YARA",
                    )
                    for finding in yara_desc_findings:
                        finding.analyzer = "YARA"
                    return yara_desc_findings, [AnalyzerEnum.YARA], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "YARA", "prompt_content", e)
                    return [], [], [], errors

            async def yara_arguments_part() -> Tuple[list, list, list, list]:
                try:
                    parameter_data = dict(prompt_data)
                    parameter_data.pop("description", None)
                    yara_params_findings = await self._wait_for_item(
                        self._yara_analyzer.analyze(
                            json.dumps(parameter_data),
                            {"prompt_name": name, "content_type": "arguments"},
                        ),
                        "YARA",
                    )
                    for finding in yara_params_findings:
                        finding.analyzer = "YARA"
                    return yara_params_findings, [AnalyzerEnum.YARA], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "YARA", "arguments", e)
                    return [], [], [], errors

            parts.append(yara_body_part)
            parts.append(yara_arguments_part)

        if AnalyzerEnum.LLM in analyzers and self._llm_analyzer:

            async def llm_part() -> Tuple[list, list, list, list]:
                try:
                    # Arguments are generated metadata. They must precede
                    # Messages: so a later body slice cannot swallow them.
                    analysis_content = f"Prompt Name: {name}\n"
                    analysis_content += f"Description: {description}\n"
                    if prompt_data.get("arguments"):
                        analysis_content += (
                            "Arguments: "
                            f"{json.dumps(prompt_data['arguments'], indent=2)}\n"
                        )
                    if prompt_messages_text:
                        analysis_content += f"Messages:\n{prompt_messages_text}\n"
                    llm_findings = await self._wait_for_item(
                        self._llm_analyzer.analyze(
                            analysis_content,
                            {
                                "prompt_name": name,
                                "content_type": "comprehensive",
                                "entity_type": "prompt",
                            },
                        ),
                        "LLM",
                    )
                    for finding in llm_findings:
                        finding.analyzer = "LLM"
                    return llm_findings, [AnalyzerEnum.LLM], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "LLM", "comprehensive", e)
                    return [], [], [], errors

            parts.append(llm_part)
        elif AnalyzerEnum.LLM in analyzers and not self._llm_analyzer:
            logger.warning(
                "LLM scan requested for prompt '%s' but LLM analyzer not "
                "initialized (MCP_SCANNER_LLM_API_KEY missing)",
                name,
            )

        if AnalyzerEnum.PROMPT_DEFENSE in analyzers and self._prompt_defense_analyzer:

            async def prompt_defense_part() -> Tuple[list, list, list, list]:
                try:
                    pd_findings = await self._wait_for_item(
                        self._prompt_defense_analyzer.analyze(
                            analyzed_text,
                            {"prompt_name": name, "content_type": "prompt_content"},
                        ),
                        "PROMPT_DEFENSE",
                    )
                    for finding in pd_findings:
                        finding.analyzer = "PromptDefense"
                    return pd_findings, [AnalyzerEnum.PROMPT_DEFENSE], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(
                        errors, "PROMPT_DEFENSE", "prompt_content", e
                    )
                    return [], [], [], errors

            parts.append(prompt_defense_part)

        for custom_analyzer in self._custom_analyzers:

            async def custom_part(
                analyzer=custom_analyzer,
            ) -> Tuple[list, list, list, list]:
                try:
                    custom_context = {
                        "prompt_name": name,
                        "content_type": "prompt_content",
                    }
                    if http_headers:
                        custom_context["http_headers"] = http_headers
                    findings = await self._wait_for_item(
                        analyzer.analyze(analyzed_text, custom_context),
                        "custom analyzer",
                    )
                    for finding in findings:
                        finding.analyzer = analyzer.name
                    return findings, [], [analyzer.name], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(
                        errors, analyzer.name, "prompt_content", e
                    )
                    return [], [], [], errors

            parts.append(custom_part)

        (
            all_findings,
            successful_analyzers,
            custom_analyzer_names,
            analyzer_errors,
        ) = await self._parallel_analyzer_parts(parts)

        # Combine enum analyzers and custom analyzer names, excluding META
        self._record_infrastructure_gaps(
            all_findings, analyzer_errors, "prompt_content"
        )
        all_analyzers, status = self._analysis_outcome(
            successful_analyzers, custom_analyzer_names, analyzer_errors
        )

        return PromptScanResult(
            prompt_name=name,
            prompt_description=description,
            status=status,
            analyzers=all_analyzers,
            findings=all_findings,
            prompt_messages_text=prompt_messages_text,
            analyzer_errors=analyzer_errors,
        )

    @_share_item_budget
    async def _analyze_instructions(
        self,
        instructions: str,
        server_name: str,
        protocol_version: str,
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict] = None,
    ) -> InstructionsScanResult:
        """Analyze server instructions using specified analyzers.

        Args:
            instructions (str): The instructions text from the server.
            server_name (str): The name of the server.
            protocol_version (str): The MCP protocol version.
            analyzers (List[AnalyzerEnum]): List of analyzers to run.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            InstructionsScanResult: The result of the analysis.
        """
        all_findings = []
        successful_analyzers: List[AnalyzerEnum] = []
        analyzer_errors: List[Dict[str, str]] = []

        if AnalyzerEnum.API in analyzers and self._api_analyzer:
            # Run API analysis on the instructions
            try:
                api_context = {
                    "server_name": server_name,
                    "content_type": "instructions",
                }
                api_findings = await self._wait_for_item(
                    self._api_analyzer.analyze(instructions, api_context),
                    "API",
                )
                for finding in api_findings:
                    finding.analyzer = "API"
                all_findings.extend(api_findings)
                successful_analyzers.append(AnalyzerEnum.API)
            except Exception as e:
                self._record_analyzer_error(analyzer_errors, "API", "instructions", e)

        if AnalyzerEnum.YARA in analyzers:
            # Run YARA analysis on the instructions
            try:
                yara_context = {
                    "server_name": server_name,
                    "content_type": "instructions",
                }
                yara_findings = await self._wait_for_item(
                    self._yara_analyzer.analyze(instructions, yara_context),
                    "YARA",
                )
                for finding in yara_findings:
                    finding.analyzer = "YARA"
                all_findings.extend(yara_findings)
                successful_analyzers.append(AnalyzerEnum.YARA)
            except Exception as e:
                self._record_analyzer_error(analyzer_errors, "YARA", "instructions", e)

        if AnalyzerEnum.LLM in analyzers and self._llm_analyzer:
            # Run LLM analysis on the instructions
            try:
                # Format content for comprehensive analysis
                analysis_content = f"Server Name: {server_name}\n"
                analysis_content += f"Protocol Version: {protocol_version}\n"
                analysis_content += f"Instructions: {instructions}\n"

                llm_context = {
                    "server_name": server_name,
                    "content_type": "instructions",
                }
                llm_findings = await self._wait_for_item(
                    self._llm_analyzer.analyze(analysis_content, llm_context),
                    "LLM",
                )
                for finding in llm_findings:
                    finding.analyzer = "LLM"
                all_findings.extend(llm_findings)
                successful_analyzers.append(AnalyzerEnum.LLM)
            except Exception as e:
                self._record_analyzer_error(analyzer_errors, "LLM", "instructions", e)
        elif AnalyzerEnum.LLM in analyzers and not self._llm_analyzer:
            logger.warning(
                f"LLM scan requested for instructions from '{server_name}' but LLM analyzer not initialized (MCP_SCANNER_LLM_API_KEY missing)"
            )

        if AnalyzerEnum.PROMPT_DEFENSE in analyzers and self._prompt_defense_analyzer:
            # Run PROMPT_DEFENSE analysis on the server instructions
            try:
                pd_context = {"tool_name": server_name, "content_type": "instructions"}
                pd_findings = await self._wait_for_item(
                    self._prompt_defense_analyzer.analyze(instructions, pd_context),
                    "PROMPT_DEFENSE",
                )
                for finding in pd_findings:
                    finding.analyzer = "PromptDefense"
                all_findings.extend(pd_findings)
                successful_analyzers.append(AnalyzerEnum.PROMPT_DEFENSE)
            except Exception as e:
                self._record_analyzer_error(
                    analyzer_errors, "PROMPT_DEFENSE", "instructions", e
                )

        # Run custom analyzers
        custom_analyzer_names = []
        for analyzer in self._custom_analyzers:
            try:
                custom_context = {
                    "server_name": server_name,
                    "content_type": "instructions",
                }
                # Add HTTP headers to context for custom analyzers
                if http_headers:
                    custom_context["http_headers"] = http_headers
                findings = await self._wait_for_item(
                    analyzer.analyze(instructions, custom_context),
                    "custom analyzer",
                )
                for finding in findings:
                    finding.analyzer = analyzer.name
                all_findings.extend(findings)
                # Track which custom analyzers were successfully run
                custom_analyzer_names.append(analyzer.name)
            except Exception as e:
                self._record_analyzer_error(
                    analyzer_errors, analyzer.name, "instructions", e
                )

        # Combine enum analyzers and custom analyzer names, excluding META
        self._record_infrastructure_gaps(all_findings, analyzer_errors, "instructions")
        all_analyzers, status = self._analysis_outcome(
            successful_analyzers, custom_analyzer_names, analyzer_errors
        )

        return InstructionsScanResult(
            instructions=instructions,
            server_name=server_name,
            protocol_version=protocol_version,
            status=status,
            analyzers=all_analyzers,
            findings=all_findings,
            analyzer_errors=analyzer_errors,
        )

    def _check_http_error_in_logs(self, msg: str) -> Optional[int]:
        """Check if a log message contains an HTTP error status code.

        Args:
            msg: Log message to check

        Returns:
            HTTP status code if found (401, 403, 404), None otherwise
        """
        if "401" in msg or "Unauthorized" in msg:
            return 401
        elif "403" in msg or "Forbidden" in msg:
            return 403
        elif "404" in msg or "Not Found" in msg:
            return 404
        return None

    async def _close_mcp_session(self, client_context, session):
        """Close MCP session and client context safely.

        Args:
            client_context: The MCP client context
            session: The MCP session
        """
        # Close session first
        if session:
            try:
                await session.__aexit__(None, None, None)
            except (
                asyncio.CancelledError,
                GeneratorExit,
                RuntimeError,
                BaseExceptionGroup,
            ):
                # Suppress cleanup errors from MCP library bugs
                # These are expected when connection fails
                pass
            except Exception as e:
                # Log unexpected errors
                if "cancel scope" not in str(e) and "TaskGroup" not in str(e):
                    logger.warning(f"Error closing session: {e}")

        # Close client context
        if client_context:
            try:
                # Ensure we're in the same task context for cleanup
                await client_context.__aexit__(None, None, None)
            except (
                asyncio.CancelledError,
                GeneratorExit,
                RuntimeError,
                BaseExceptionGroup,
            ):
                # Suppress cleanup errors from MCP library bugs
                # These are expected when connection fails
                pass
            except Exception as e:
                # Log unexpected errors
                if "cancel scope" not in str(e) and "TaskGroup" not in str(e):
                    logger.warning(f"Error closing client context: {e}")

            # Explicitly close the httpx.AsyncClient we created, in case the
            # MCP library's own cleanup failed (e.g. session termination
            # DELETE returned 404 and the task group teardown left the
            # client unclosed).
            httpx_client = getattr(client_context, "_httpx_client", None)
            if httpx_client and not httpx_client.is_closed:
                try:
                    await httpx_client.aclose()
                except Exception:
                    pass

    async def _get_mcp_session(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        *,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Tuple[Any, ClientSession]:
        """Create an MCP client session for the given server URL.

        Args:
            server_url (str): The URL of the MCP server.
            auth (Optional[Auth]): Explicit authentication configuration. If None, connects without auth.
            connector_id (Optional[str]): Hybrid connector ID for private MCP servers.
            tenant_id (Optional[str]): Tenant ID for hybrid proxy relay routing.

        Returns:
            tuple: A tuple containing (client_context, session)

        Raises:
            ConnectionError: If unable to connect to the MCP server
        """
        oauth_provider = None
        extra_headers: Dict[str, str] = {}

        # Only use authentication if explicitly provided via Auth parameter
        if auth is not None:
            if auth and auth.type == AuthType.OAUTH:
                logger.debug(
                    f'Using explicit OAuth authentication for MCP server: server="{server_url}"'
                )
                oauth_provider = create_oauth_provider_from_auth(auth, server_url)
            elif auth and auth.type == AuthType.BEARER:
                if not getattr(auth, "bearer_token", None):
                    raise ValueError(
                        "Bearer authentication selected but no bearer_token provided"
                    )
                # Prepare Authorization header for bearer token auth
                extra_headers["Authorization"] = f"Bearer {auth.bearer_token}"
                logger.debug(
                    f'Using explicit Bearer authentication for MCP server: server="{server_url}"'
                )
            elif auth and auth.type == AuthType.APIKEY:
                if not getattr(auth, "api_key", None) or not getattr(
                    auth, "api_key_header", None
                ):
                    raise ValueError(
                        "APIKEY authentication selected but no api key or api header value provided"
                    )
                extra_headers[auth.api_key_header] = auth.api_key
                logger.debug(
                    f'Using APIKEY authentication for MCP server: server="{server_url}"'
                )

            # Add any custom headers from Auth object (works with any auth type)
            if hasattr(auth, "custom_headers") and auth.custom_headers:
                extra_headers.update(auth.custom_headers)
        else:
            logger.debug(
                f'No explicit auth provided, connecting without authentication: server="{server_url}"'
            )

        destination_url = server_url
        dial_url, extra_headers = prepare_mcp_dial(
            destination_url,
            extra_headers,
            connector_id,
            tenant_id,
            streaming=True,
        )
        if is_hybrid_connector_id(connector_id):
            logger.debug(
                f'Using hybrid proxy relay for MCP server: destination="{destination_url}"'
            )

        # Create client context with or without OAuth
        # For streamable HTTP, create an explicit httpx.AsyncClient so we can
        # guarantee it gets closed even if the MCP library's internal cleanup
        # fails (e.g. session termination DELETE returns 404).
        httpx_client = None
        if oauth_provider:
            if "/sse" in destination_url:
                client_context = (
                    sse_client(dial_url, headers=extra_headers, auth=oauth_provider)
                    if extra_headers
                    else sse_client(dial_url, auth=oauth_provider)
                )
            else:
                httpx_client = create_mcp_http_client(
                    headers=extra_headers if extra_headers else None,
                    auth=oauth_provider,
                )
                client_context = streamable_http_client(
                    dial_url, http_client=httpx_client
                )
        else:
            logger.debug(
                f'Using standard connection (no auth) for MCP server: server="{destination_url}"'
            )
            # Pass bearer Authorization header when requested
            if "/sse" in destination_url:
                client_context = (
                    sse_client(dial_url, headers=extra_headers)
                    if extra_headers
                    else sse_client(dial_url)
                )
            else:
                httpx_client = create_mcp_http_client(
                    headers=extra_headers if extra_headers else None
                )
                client_context = streamable_http_client(
                    dial_url, http_client=httpx_client
                )

        # Stash the httpx client on the context so _close_mcp_session can close it
        client_context._httpx_client = httpx_client

        client_context_opened = None
        session = None
        http_status_code = None
        capture_handler = None
        httpx_logger = None
        original_httpx_level = None
        original_propagate = None

        # Set up httpx logging capture to detect HTTP errors
        httpx_logger = stdlib_logging.getLogger("httpx")
        original_httpx_level = httpx_logger.level
        original_propagate = httpx_logger.propagate

        class StatusCodeCapture(stdlib_logging.Handler):
            def __init__(self):
                super().__init__(level=stdlib_logging.INFO)

            def emit(self, record):
                nonlocal http_status_code
                # Capture the status code silently (don't propagate to console)
                http_status_code = (
                    self._check_http_error_in_logs(record.getMessage())
                    or http_status_code
                )

        capture_handler = StatusCodeCapture()
        capture_handler._check_http_error_in_logs = self._check_http_error_in_logs

        # Temporarily set httpx logger to INFO to ensure it emits logs we can capture
        # Disable propagation only if we're raising the log level to avoid console output
        httpx_logger.addHandler(capture_handler)
        if (
            httpx_logger.level > stdlib_logging.INFO
            or httpx_logger.level == stdlib_logging.NOTSET
        ):
            httpx_logger.setLevel(stdlib_logging.INFO)
            httpx_logger.propagate = False  # Prevent console output

        try:
            logger.debug(f'Attempting to connect to MCP server: server="{server_url}"')

            async def _establish_session() -> None:
                nonlocal client_context_opened, session
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        category=RuntimeWarning,
                        message=".*async.*generator.*",
                    )
                    client_context_opened = await client_context.__aenter__()
                    streams = client_context_opened
                    read, write, *_ = streams
                    session = ClientSession(read, write)
                    await session.__aenter__()
                    logger.debug(f'Initializing MCP session: server="{server_url}"')
                    await self._negotiate_mcp_session(
                        session, legacy_http="/sse" not in destination_url
                    )

            try:
                # asyncio.timeout stays on this task. wait_for would enter
                # the anyio cancel scopes on a short-lived task, and closing
                # them from here would raise on Python 3.11.
                async with asyncio.timeout(
                    float(MCPScannerConstants.MCP_SESSION_TIMEOUT_SECONDS)
                ):
                    await _establish_session()
            except TimeoutError as exc:
                await self._close_mcp_session(client_context, session)
                raise MCPConnectionError(
                    f"Timed out connecting to MCP server at {server_url} "
                    f"after {MCPScannerConstants.MCP_SESSION_TIMEOUT_SECONDS:g}s."
                ) from exc
            logger.debug(f'Successfully connected to MCP server: server="{server_url}"')
            return client_context, session
        except (asyncio.CancelledError, GeneratorExit) as e:
            # These exceptions often wrap HTTP errors from the MCP library
            await self._close_mcp_session(client_context, session)

            # Check if we captured an HTTP error status code from logs
            if http_status_code == 401:
                raise MCPAuthenticationError(
                    f"Authentication failed for MCP server at {server_url}. "
                    f"This server requires OAuth or Bearer token authentication. "
                    f"Use --bearer-token <token> or configure OAuth."
                ) from e
            elif http_status_code == 403:
                raise MCPAuthenticationError(
                    f"Access denied to MCP server at {server_url}. "
                    f"Check your authentication credentials."
                ) from e
            elif http_status_code == 404:
                raise MCPServerNotFoundError(
                    f"MCP server endpoint not found at {server_url}. "
                    f"Please verify the URL is correct."
                ) from e

            # Generic cancellation error
            raise MCPConnectionError(
                f"Connection to MCP server at {server_url} was cancelled. "
                f"This may indicate the server is not reachable, not responding, or requires authentication."
            ) from e
        except BaseExceptionGroup as eg:
            # ExceptionGroup from MCP library - check for HTTP errors
            await self._close_mcp_session(client_context, session)

            # Get the first error for inspection
            first_error = eg.exceptions[0] if eg.exceptions else eg
            error_str = str(first_error)

            # Check if we captured an HTTP error status code from logs, or check error string
            detected_code = http_status_code or self._check_http_error_in_logs(
                error_str
            )

            if detected_code == 401:
                raise MCPAuthenticationError(
                    f"Authentication failed for MCP server at {server_url}. "
                    f"This server requires OAuth or Bearer token authentication. "
                    f"Use --bearer-token <token> or configure OAuth. "
                    f"Original error: {first_error}"
                ) from eg
            elif detected_code == 403:
                raise MCPAuthenticationError(
                    f"Access denied to MCP server at {server_url}. "
                    f"Check your authentication credentials. "
                    f"Original error: {first_error}"
                ) from eg
            elif detected_code == 404:
                raise MCPServerNotFoundError(
                    f"MCP server endpoint not found at {server_url}. "
                    f"Please verify the URL is correct. "
                    f"Original error: {first_error}"
                ) from eg

            # Generic ExceptionGroup error
            raise MCPConnectionError(
                f"Error connecting to MCP server at {server_url}: {first_error}"
            ) from eg
        except Exception as e:
            # Try to clean up resources on any error
            await self._close_mcp_session(client_context, session)
            # Convert connection errors to more user-friendly messages
            if (
                "ConnectError" in str(type(e))
                or "connection" in str(e).lower()
                or "nodename nor servname" in str(e)
            ):
                raise MCPConnectionError(
                    f"Unable to connect to MCP server at {server_url}. "
                    f"Please verify the server is running and accessible. "
                    f"Original error: {e}"
                ) from e
            raise
        finally:
            # Clean up httpx logger handler and restore original settings
            if capture_handler and httpx_logger:
                httpx_logger.removeHandler(capture_handler)
                if original_httpx_level is not None:
                    httpx_logger.setLevel(original_httpx_level)
                if original_propagate is not None:
                    httpx_logger.propagate = original_propagate

    async def scan_remote_server_tool(
        self,
        server_url: str,
        tool_name: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
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
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = self.DEFAULT_ANALYZERS

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url,
                auth,
                connector_id=connector_id,
                tenant_id=tenant_id,
            )

            # List all tools and find the target tool
            try:
                tools, list_gap = await self._list_mcp_items(
                    session,
                    "tools",
                    server_url,
                    stop_when=lambda tool: getattr(tool, "name", None) == tool_name,
                )
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = f"Server '{server_url}' does not expose tools; cannot scan '{tool_name}'."
                    logger.warning(message)
                    raise ValueError(message) from e
                raise
            target_tool = self._missing_listed_item(
                next((t for t in tools if t.name == tool_name), None),
                list_gap,
                f"Tool '{tool_name}' not found on the server at {server_url}",
            )

            async with self._item_budget_scope():
                result = await self._analyze_tool(target_tool, analyzers, http_headers)
                result = await self._run_meta_analysis_on_single_tool(result, analyzers)
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning tool \'{tool_name}\' on MCP server: server="{server_url}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def _prepare_remote_catalog(
        self,
        kind: str,
        server_url: str,
        auth: Optional[Auth],
        analyzers: List[AnalyzerEnum],
        connector_id: Optional[str],
        tenant_id: Optional[str],
    ) -> Tuple["_HeldMcpSession", list, Optional[str]]:
        """Open a session and list one capability before a stream starts.

        Failures here are the same exceptions as a non-streaming scan, so the
        HTTP layer can map them to status codes before the first body byte.
        The caller owns the held session and must close it. Closing is safe
        more than once.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )
        self._validate_analyzer_requirements(analyzers)
        client_context = None
        session = None
        held: Optional[_HeldMcpSession] = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url,
                auth,
                connector_id=connector_id,
                tenant_id=tenant_id,
            )
            held = _HeldMcpSession(self, client_context, session)
            if (
                kind != "tools"
                and self._server_supports_capability(session, kind) is False
            ):
                return held, [], None
            try:
                items, list_gap = await self._list_mcp_items(session, kind, server_url)
            except McpError as e:
                if self._is_missing_capability_error(e):
                    logger.warning(
                        "Server '%s' does not expose %s: %s",
                        server_url,
                        kind,
                        type(e).__name__,
                    )
                    return held, [], None
                raise
            return held, list(items), list_gap
        except BaseException:
            if held is not None:
                await held.close()
            else:
                await self._close_mcp_session(client_context, session)
            raise

    async def _stream_open_session(
        self,
        held: "_HeldMcpSession",
        produce: Callable[[ClientSession, asyncio.Queue], Awaitable[None]],
        release_session: bool = True,
    ) -> AsyncIterator[Any]:
        """Stream results from a session opened by ``_prepare_remote_catalog``.

        ``release_session`` is false for the HTTP stream. The session was
        opened on the request task, and the body runs on a child of
        Starlette's response task group. Closing the MCP client there
        cancels that group before the chunked body finishes. The response
        closes the session on the request task after the body is sent.
        """
        session = held.session
        queue: asyncio.Queue = asyncio.Queue(
            maxsize=max(1, int(MCPScannerConstants.STREAM_QUEUE_SIZE))
        )
        finished = object()
        producer = None
        try:

            async def run() -> None:
                try:
                    await produce(session, queue)
                finally:
                    current = asyncio.current_task()
                    if current is not None and current.cancelling():
                        _signal_stream_end(queue, finished)
                    else:
                        await queue.put(finished)

            producer = asyncio.create_task(run())
            while True:
                item = await queue.get()
                if item is finished:
                    break
                yield item
            await producer
        finally:
            # One window covers the producer wait and the session close.
            # Restoring cancellation between them cancels the close on
            # Python 3.11 and 3.12 before the session is torn down.
            async with _cancellation_window():
                if producer is not None and not producer.done():
                    producer.cancel()
                    await _await_cancelled_tasks([producer])
                if release_session:
                    await held.close()

    async def _failed_tool_result(
        self, tool: MCPTool, error: Exception
    ) -> ToolScanResult:
        """One tool failure stays a result and does not stop the other tools."""
        logger.error(
            "Error analyzing tool '%s': %s",
            getattr(tool, "name", ""),
            type(error).__name__,
        )
        finding = build_infrastructure_error_finding(
            analyzer_name="MCP",
            subject=getattr(tool, "name", "") or "tool",
            error=error,
            context="local",
        )
        return ToolScanResult(
            tool_name=getattr(tool, "name", "") or "",
            tool_description=getattr(tool, "description", "") or "",
            status="failed",
            analyzers=[],
            findings=[finding],
        )

    def iter_remote_server_tools(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> _SameTaskAsyncIter:
        """Yield each tool result as it finishes. List order is not preserved.

        Close the iterator with ``async with`` or ``aclose``. A bare
        ``async for`` that breaks does not close the MCP session.
        """

        async def generate() -> AsyncIterator[Any]:
            selected = analyzers
            if selected is None:
                selected = self.DEFAULT_ANALYZERS
            prepared = await self._prepare_remote_catalog(
                "tools",
                server_url,
                auth,
                selected,
                connector_id,
                tenant_id,
            )
            async for item in self._iter_prepared_tools(
                prepared, selected, http_headers
            ):
                yield item

        return _SameTaskAsyncIter(generate())

    async def _iter_prepared_tools(
        self,
        prepared: Tuple["_HeldMcpSession", list, Optional[str]],
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict],
        release_session: bool = True,
    ) -> AsyncIterator[Any]:
        """Yield tool results for a catalog opened before the response starts."""
        held, tools, list_gap = prepared

        async def produce(session: ClientSession, queue: asyncio.Queue) -> None:
            await queue.put(ScanListNotice(len(tools), list_gap is None))
            scan_sem = asyncio.Semaphore(self._remote_scan_limit())
            meta_sem = asyncio.Semaphore(self._META_CONCURRENCY)
            tasks: List[asyncio.Task] = []

            async def one(tool: MCPTool) -> None:
                try:
                    result = await self._analyze_tool_for_scan(
                        tool, analyzers, http_headers, scan_sem, meta_sem
                    )
                except Exception as e:
                    result = await self._failed_tool_result(tool, e)
                await queue.put(result)

            tasks = [asyncio.create_task(one(tool)) for tool in tools]
            try:
                if tasks:
                    await asyncio.gather(*tasks)
                if list_gap:
                    gap: List[Any] = []
                    self._append_list_gap(gap, "tools", list_gap)
                    await queue.put(gap[0])
            finally:
                await _await_cancelled_tasks(tasks)

        async for item in self._stream_open_session(
            held, produce, release_session=release_session
        ):
            yield item

    def iter_remote_server_prompts(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> _SameTaskAsyncIter:
        """Yield each prompt result as it finishes. List order is not preserved.

        Close the iterator with ``async with`` or ``aclose``. A bare
        ``async for`` that breaks does not close the MCP session.
        """

        async def generate() -> AsyncIterator[Any]:
            selected = analyzers
            if selected is None:
                selected = [AnalyzerEnum.API, AnalyzerEnum.LLM]
            prepared = await self._prepare_remote_catalog(
                "prompts",
                server_url,
                auth,
                selected,
                connector_id,
                tenant_id,
            )
            async for item in self._iter_prepared_prompts(
                prepared, selected, http_headers
            ):
                yield item

        return _SameTaskAsyncIter(generate())

    async def _iter_prepared_prompts(
        self,
        prepared: Tuple["_HeldMcpSession", list, Optional[str]],
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict],
        release_session: bool = True,
    ) -> AsyncIterator[Any]:
        """Yield prompt results for a catalog opened before the response starts."""
        held, prompts, list_gap = prepared

        async def produce(session: ClientSession, queue: asyncio.Queue) -> None:
            await queue.put(ScanListNotice(len(prompts), list_gap is None))
            await self._fetch_and_analyze_prompts(
                session, prompts, analyzers, http_headers, sink=queue
            )
            if list_gap:
                gap: List[Any] = []
                self._append_list_gap(gap, "prompts", list_gap)
                await queue.put(gap[0])

        async for item in self._stream_open_session(
            held, produce, release_session=release_session
        ):
            yield item

    def iter_remote_server_resources(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        allowed_mime_types: Optional[List[str]] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> _SameTaskAsyncIter:
        """Yield each resource result as it finishes. List order is not preserved.

        Close the iterator with ``async with`` or ``aclose``. A bare
        ``async for`` that breaks does not close the MCP session.
        """

        async def generate() -> AsyncIterator[Any]:
            selected = analyzers
            if selected is None:
                selected = [*self.DEFAULT_ANALYZERS, AnalyzerEnum.LLM]
            mime_types = allowed_mime_types
            if mime_types is None:
                mime_types = ["text/plain", "text/html"]
            prepared = await self._prepare_remote_catalog(
                "resources",
                server_url,
                auth,
                selected,
                connector_id,
                tenant_id,
            )
            async for item in self._iter_prepared_resources(
                prepared, selected, http_headers, mime_types
            ):
                yield item

        return _SameTaskAsyncIter(generate())

    async def _iter_prepared_resources(
        self,
        prepared: Tuple["_HeldMcpSession", list, Optional[str]],
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict],
        allowed_mime_types: List[str],
        release_session: bool = True,
    ) -> AsyncIterator[Any]:
        """Yield resource results for a catalog opened before the response starts."""
        held, resources, list_gap = prepared

        async def produce(session: ClientSession, queue: asyncio.Queue) -> None:
            await queue.put(ScanListNotice(len(resources), list_gap is None))
            await self._scan_listed_resources(
                session,
                resources,
                analyzers,
                http_headers,
                allowed_mime_types,
                sink=queue,
            )
            if list_gap:
                gap: List[Any] = []
                self._append_list_gap(gap, "resources", list_gap)
                await queue.put(gap[0])

        async for item in self._stream_open_session(
            held, produce, release_session=release_session
        ):
            yield item

    async def scan_remote_server_tools(
        self,
        server_url: str,
        auth: Optional[Auth] = None,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        http_headers: Optional[dict] = None,
        connector_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
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
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to all analyzers if none specified
        if analyzers is None:
            analyzers = self.DEFAULT_ANALYZERS

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url,
                auth,
                connector_id=connector_id,
                tenant_id=tenant_id,
            )

            # List all tools
            try:
                tools, list_gap = await self._list_mcp_items(
                    session, "tools", server_url
                )
            except McpError as e:
                if self._is_missing_capability_error(e):
                    logger.warning(f"Server '{server_url}' does not expose tools: {e}")
                    return []
                raise

            results = await self._analyze_tools_bounded(tools, analyzers, http_headers)
            if list_gap:
                self._append_list_gap(results, "tools", list_gap)
            return results

        except Exception as e:
            logger.error(f"Error scanning server {server_url}: {e}")
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    async def _get_stdio_session(
        self, server_config: StdioServer, timeout: int = 30, errlog: Any = None
    ) -> Tuple[Any, Any]:
        """Get a stdio session for the given server configuration.

        Args:
            server_config: The stdio server configuration
            timeout: Connection timeout in seconds
            errlog: Optional file-like object for stderr redirection (defaults to sys.stderr)

        Returns:
            Tuple of (client_context, session)
        """
        client_context = None
        session = None

        try:
            logger.debug(f"Creating stdio client for command: {server_config.command}")

            # Normalize and validate command/args to avoid FileNotFoundError ([Errno 2])
            # Expansion mode comes from StdioServer config; default is 'off'
            expand_mode = (server_config.expand_vars or "off").lower()
            logger.debug(
                f"expand_mode='{expand_mode}' for command: {server_config.command}"
            )
            env_for_expansion = build_env_for_expansion(server_config.env)
            windows_semantics = decide_windows_semantics(expand_mode)

            expanded_command, expanded_args = normalize_and_expand_command_args(
                server_config.command or "",
                server_config.args or [],
                env_for_expansion,
                expand_mode,
            )
            cmd_command, cmd_args = split_embedded_args(
                expanded_command, expanded_args, windows_semantics
            )
            resolved_exe = resolve_executable_path(cmd_command)
            if not resolved_exe or not os.path.exists(resolved_exe):
                # Provide a clear, actionable message and fail fast for this server only
                msg = (
                    f"No such file or command: '{server_config.command}'. "
                    f"Resolved path: '{resolved_exe or 'N/A'}'. "
                    f"Tip: use absolute paths or ensure the binary is on PATH."
                )
                logger.warning(msg)
                raise MCPConnectionError(
                    f"Unable to connect to stdio MCP server with command {server_config.command}. "
                    f"Please verify the command is correct and executable."
                )

            # 5) Build parameters with normalized command/args
            # Merge parent process env with server-specific env (server config takes precedence)
            merged_env = {**os.environ, **(server_config.env or {})}
            server_params = StdioServerParameters(
                command=resolved_exe,
                args=cmd_args,
                env=merged_env,
            )

            # Create client context and session with proper error handling
            # Pass errlog for stderr redirection (helps avoid JSON corruption from startup messages)
            client_context = stdio_client(
                server_params, errlog=errlog if errlog else sys.stderr
            )

            # Enter both context managers on this task. wait_for would
            # enter their anyio cancel scopes on another task.
            try:
                async with asyncio.timeout(timeout):
                    client_context_opened = await client_context.__aenter__()
                read, write = client_context_opened

                session = ClientSession(read, write)
                async with asyncio.timeout(10):
                    await session.__aenter__()
                await asyncio.wait_for(
                    self._negotiate_mcp_session(session, legacy_stdio=True),
                    timeout=10,
                )

            except asyncio.TimeoutError:
                # Clean up on timeout
                if session:
                    try:
                        await session.__aexit__(None, None, None)
                    except:
                        pass
                if client_context:
                    try:
                        await client_context.__aexit__(None, None, None)
                    except:
                        pass
                raise

            logger.debug(
                f"Successfully connected to stdio MCP server: {server_config.command}"
            )
            return client_context, session

        except asyncio.TimeoutError:
            logger.error(
                f"Timeout connecting to stdio server {server_config.command} after {timeout}s"
            )
            raise MCPConnectionError(
                f"Timeout connecting to stdio MCP server with command {server_config.command}. "
                f"Server took longer than {timeout} seconds to start."
            )
        except asyncio.CancelledError:
            logger.error(
                f"Connection cancelled for stdio server {server_config.command}"
            )
            # Clean up resources on cancellation
            if session:
                try:
                    await session.__aexit__(None, None, None)
                except:
                    pass
            if client_context:
                try:
                    await client_context.__aexit__(None, None, None)
                except:
                    pass
            raise MCPConnectionError(
                f"Connection cancelled for stdio MCP server with command {server_config.command}. "
                f"This may indicate the server failed to start properly."
            )
        except Exception as e:
            logger.error(
                f"Error connecting to stdio server {server_config.command}: {e}"
            )
            # Clean up resources on error
            if session:
                try:
                    await session.__aexit__(None, None, None)
                except:
                    pass
            if client_context:
                try:
                    await client_context.__aexit__(None, None, None)
                except:
                    pass
            raise MCPConnectionError(
                f"Unable to connect to stdio MCP server with command {server_config.command}. "
                f"Please verify the command is correct and executable. "
                f"Original error: {e}"
            ) from e

    async def scan_stdio_server_tools(
        self,
        server_config: StdioServer,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
        errlog: Any = None,
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

        client_context = None
        session = None
        try:
            # Create a new task for the connection to isolate async contexts
            async def connect_and_scan():
                nonlocal client_context, session
                client_context, session = await self._get_stdio_session(
                    server_config, timeout, errlog
                )

                # List all tools
                try:
                    tools, list_gap = await self._list_mcp_items(
                        session, "tools", server_config.command, timeout=timeout
                    )
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            f"Stdio server '{server_config.command}' does not expose tools: {e}"
                        )
                        return []
                    raise

                results = await self._analyze_tools_bounded(tools, analyzers)
                if list_gap:
                    self._append_list_gap(results, "tools", list_gap)
                return results

            # Run the connection and scanning in an isolated task
            return await connect_and_scan()

        except Exception as e:
            logger.error(f"Error scanning stdio server {server_config.command}: {e}")
            raise
        finally:
            # Always clean up resources
            await self._close_mcp_session(client_context, session)

    async def scan_stdio_server_tool(
        self,
        server_config: StdioServer,
        tool_name: str,
        analyzers: Optional[List[AnalyzerEnum]] = None,
        timeout: Optional[int] = None,
        errlog: Any = None,
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

        client_context = None
        session = None
        try:
            client_context, session = await self._get_stdio_session(
                server_config, timeout, errlog
            )

            # List all tools and find the target tool
            try:
                tools, list_gap = await self._list_mcp_items(
                    session,
                    "tools",
                    server_config.command,
                    timeout=timeout,
                    stop_when=lambda tool: getattr(tool, "name", None) == tool_name,
                )
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = f"Stdio server '{server_config.command}' does not expose tools; cannot scan '{tool_name}'."
                    logger.warning(message)
                    raise ValueError(message) from e
                raise
            target_tool = self._missing_listed_item(
                next((t for t in tools if t.name == tool_name), None),
                list_gap,
                (
                    f"Tool '{tool_name}' not found on the stdio server "
                    f"with command {server_config.command}"
                ),
            )

            async with self._item_budget_scope():
                result = await self._analyze_tool(target_tool, analyzers)
                result = await self._run_meta_analysis_on_single_tool(result, analyzers)
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning tool \'{tool_name}\' on stdio server: command="{server_config.command}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

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
            logger.debug(f"Scanning servers from config: {config_path}")
            servers = config_scanner.extract_servers(config)
            config_results = []

            for server_name, server_config in servers.items():
                logger.debug(f"Scanning server '{server_name}' from {config_path}")

                try:
                    if isinstance(server_config, StdioServer):
                        # Apply default expand mode if not provided by config
                        if expand_vars_default and not server_config.expand_vars:
                            logger.debug(
                                f"Applying expand_vars='{expand_vars_default}' to server '{server_name}'"
                            )
                            server_config.expand_vars = expand_vars_default
                        else:
                            logger.debug(
                                f"Server '{server_name}' expand_vars: {server_config.expand_vars} (default: {expand_vars_default})"
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
                                f"Failed to connect to server '{server_name}': {e}"
                            )
                            logger.debug(f"Continuing with remaining servers...")
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
                                f"Failed to connect to server '{server_name}': {e}"
                            )
                            logger.debug(f"Continuing with remaining servers...")
                            continue
                    else:
                        logger.warning(
                            f"Unknown server type for '{server_name}' in {config_path}"
                        )

                except Exception as e:
                    logger.error(
                        f"Unexpected error scanning server '{server_name}' from {config_path}: {e}"
                    )
                    logger.debug(f"Continuing with remaining servers...")
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
            logger.debug(f"Scanning server '{server_name}' from {config_path}")

            try:
                if isinstance(server_config, StdioServer):
                    # Apply default expand mode if not provided by config
                    if expand_vars_default and not server_config.expand_vars:
                        logger.debug(
                            f"Applying expand_vars='{expand_vars_default}' to server '{server_name}'"
                        )
                        server_config.expand_vars = expand_vars_default
                    else:
                        logger.debug(
                            f"Server '{server_name}' expand_vars: {server_config.expand_vars} (default: {expand_vars_default})"
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
                            f"Failed to connect to server '{server_name}': {e}"
                        )
                        logger.debug(f"Continuing with remaining servers...")
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
                            f"Failed to connect to server '{server_name}': {e}"
                        )
                        logger.debug(f"Continuing with remaining servers...")
                        continue
                else:
                    logger.warning(
                        f"Unknown server type for '{server_name}' in {config_path}"
                    )

            except Exception as e:
                logger.error(
                    f"Unexpected error scanning server '{server_name}' from {config_path}: {e}"
                )
                logger.debug(f"Continuing with remaining servers...")
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
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url,
                auth,
                connector_id=connector_id,
                tenant_id=tenant_id,
            )

            # Capability gate: see scan_remote_server_resources for rationale.
            if self._server_supports_capability(session, "prompts") is False:
                logger.info(
                    f"Server '{server_url}' did not advertise prompts capability; skipping prompt scan"
                )
                return []

            # List all prompts
            try:
                prompts, list_gap = await self._list_mcp_items(
                    session, "prompts", server_url
                )
            except McpError as e:
                if self._is_missing_capability_error(e):
                    logger.warning(
                        f"Server '{server_url}' does not expose prompts: {e}"
                    )
                    return []
                raise

            results = await self._fetch_and_analyze_prompts(
                session, prompts, analyzers, http_headers
            )
            if list_gap:
                self._append_list_gap(results, "prompts", list_gap)
            return results

        except Exception as e:
            logger.error(f"Error scanning prompts on server {server_url}: {e}")
            raise
        finally:
            await self._close_mcp_session(client_context, session)

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
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to API and LLM analyzers for prompts
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url,
                auth,
                connector_id=connector_id,
                tenant_id=tenant_id,
            )

            # Capability gate (same rationale as scan_remote_server_prompts).
            if self._server_supports_capability(session, "prompts") is False:
                message = f"Server '{server_url}' did not advertise prompts capability; cannot scan '{prompt_name}'."
                logger.warning(message)
                raise ValueError(message)

            # List all prompts and find the target prompt
            try:
                prompts, list_gap = await self._list_mcp_items(
                    session,
                    "prompts",
                    server_url,
                    stop_when=lambda prompt: getattr(prompt, "name", None)
                    == prompt_name,
                )
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = f"Server '{server_url}' does not expose prompts; cannot scan '{prompt_name}'."
                    logger.warning(message)
                    raise ValueError(message) from e
                raise
            target_prompt = self._missing_listed_item(
                next((p for p in prompts if p.name == prompt_name), None),
                list_gap,
                f"Prompt '{prompt_name}' not found on the server at {server_url}",
            )

            prompt_messages_text, fetch_error = (
                await self._resolve_prompt_messages_text(session, target_prompt)
            )
            async with self._item_budget_scope():
                if fetch_error is not None:
                    result = self._prompt_messages_fetch_failure_result(
                        target_prompt, fetch_error, analyzers
                    )
                else:
                    result = await self._analyze_prompt(
                        target_prompt,
                        analyzers,
                        http_headers,
                        prompt_messages_text=prompt_messages_text,
                    )
                result = await self._run_meta_analysis_on_single_prompt(
                    result, analyzers
                )
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning prompt \'{prompt_name}\' on MCP server: server="{server_url}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

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
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default to all analyzers including LLM for instructions
        # Instructions benefit from semantic analysis
        if analyzers is None:
            analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url,
                auth,
                connector_id=connector_id,
                tenant_id=tenant_id,
            )

            # Connect result is stashed on the session during negotiation.
            instructions, server_info, protocol_version = (
                self._session_connect_metadata(session)
            )

            if protocol_version is None and not getattr(session, "_init_result", None):
                raise ValueError(
                    f"Failed to get initialization result from server at {server_url}"
                )

            if not instructions:
                # Return a result with no findings if instructions are not provided
                logger.info(
                    f"Server at {server_url} does not provide instructions field"
                )
                return InstructionsScanResult(
                    instructions="",
                    server_name=(
                        getattr(server_info, "name", "Unknown")
                        if server_info is not None
                        else "Unknown"
                    ),
                    protocol_version=protocol_version or "Unknown",
                    status="skipped",
                    analyzers=[],
                    findings=[],
                )

            server_name = (
                getattr(server_info, "name", "Unknown")
                if server_info is not None
                else "Unknown"
            )
            protocol_version = protocol_version or "Unknown"

            async with self._item_budget_scope():
                result = await self._analyze_instructions(
                    instructions=instructions,
                    server_name=server_name,
                    protocol_version=protocol_version,
                    analyzers=analyzers,
                    http_headers=http_headers,
                )
                result = await self._run_meta_analysis_on_instructions_result(
                    result, analyzers
                )
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning instructions on MCP server: server="{server_url}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

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

        client_context = None
        session = None
        try:
            # Create a new task for the connection to isolate async contexts
            async def connect_and_scan():
                nonlocal client_context, session
                client_context, session = await self._get_stdio_session(
                    server_config, timeout, errlog
                )

                # List all prompts
                try:
                    prompts, list_gap = await self._list_mcp_items(
                        session, "prompts", server_config.command, timeout=timeout
                    )
                except McpError as e:
                    if self._is_missing_capability_error(e):
                        logger.warning(
                            f"Stdio server '{server_config.command}' does not expose prompts: {e}"
                        )
                        return []
                    raise

                results = await self._fetch_and_analyze_prompts(
                    session, prompts, analyzers
                )
                if list_gap:
                    self._append_list_gap(results, "prompts", list_gap)
                return results

            # Run the connection and scanning in an isolated task
            return await connect_and_scan()

        except Exception as e:
            logger.error(
                f"Error scanning prompts on stdio server {server_config.command}: {e}"
            )
            raise
        finally:
            # Always clean up resources
            await self._close_mcp_session(client_context, session)

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

        client_context = None
        session = None
        try:
            client_context, session = await self._get_stdio_session(
                server_config, timeout, errlog
            )

            # List all prompts and find the target prompt
            try:
                prompts, list_gap = await self._list_mcp_items(
                    session,
                    "prompts",
                    server_config.command,
                    timeout=timeout,
                    stop_when=lambda prompt: getattr(prompt, "name", None)
                    == prompt_name,
                )
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = f"Stdio server '{server_config.command}' does not expose prompts; cannot scan '{prompt_name}'."
                    logger.warning(message)
                    raise ValueError(message) from e
                raise
            target_prompt = self._missing_listed_item(
                next((p for p in prompts if p.name == prompt_name), None),
                list_gap,
                (
                    f"Prompt '{prompt_name}' not found on the stdio server "
                    f"with command {server_config.command}"
                ),
            )

            prompt_messages_text, fetch_error = (
                await self._resolve_prompt_messages_text(session, target_prompt)
            )
            async with self._item_budget_scope():
                if fetch_error is not None:
                    result = self._prompt_messages_fetch_failure_result(
                        target_prompt, fetch_error, analyzers
                    )
                else:
                    result = await self._analyze_prompt(
                        target_prompt,
                        analyzers,
                        prompt_messages_text=prompt_messages_text,
                    )
                result = await self._run_meta_analysis_on_single_prompt(
                    result, analyzers
                )
            return result

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f'Error scanning prompt \'{prompt_name}\' on stdio server: command="{server_config.command}", error="{e}"'
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)

    @_share_item_budget
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
        """Analyze a single MCP resource using specified analyzers.

        Args:
            resource_content (str): The content of the resource to analyze.
            resource_uri (str): The URI of the resource.
            resource_name (str): The name of the resource.
            resource_description (str): The description of the resource.
            resource_mime_type (str): The MIME type of the resource.
            analyzers (List[AnalyzerEnum]): List of analyzers to run on resource body text.
            http_headers (Optional[dict]): Optional HTTP headers to pass to analyzers.

        Returns:
            ResourceScanResult: The result of the analysis.
        """
        all_findings = []
        successful_analyzers: List[AnalyzerEnum] = []
        analyzer_errors: List[Dict[str, str]] = []
        bounded_content, limit_error = self._apply_body_budget(
            resource_content,
            MCPScannerConstants.MAX_RESOURCE_BODY_CHARS,
            MCPScannerConstants.MAX_PROMPT_RESOURCE_AGGREGATE_CHARS,
        )
        if limit_error is not None:
            return self._resource_coverage_limit_result(
                resource_uri,
                resource_name,
                resource_mime_type,
                limit_error,
            )
        resource_content = bounded_content

        # Extract text from HTML if needed
        analysis_content = resource_content
        if resource_mime_type == "text/html":
            try:
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(resource_content, "html.parser")
                # Extract text content from HTML
                analysis_content = soup.get_text(separator="\n", strip=True)
                logger.info(f"Extracted text from HTML resource: {resource_uri}")
            except ImportError:
                logger.warning(
                    "BeautifulSoup not installed, analyzing raw HTML content"
                )
                analysis_content = resource_content
            except (ValueError, TypeError) as e:
                logger.warning(
                    f"Error parsing HTML for resource '{resource_uri}': {e}. Using raw content."
                )
                analysis_content = resource_content
            except Exception as e:
                logger.error(
                    f"Unexpected error extracting text from HTML '{resource_uri}': {e}. Using raw content."
                )
                analysis_content = resource_content

        parts = []
        base_context = {
            "resource_uri": resource_uri,
            "resource_name": resource_name,
            "resource_description": resource_description,
            "mime_type": resource_mime_type,
        }

        if AnalyzerEnum.API in analyzers and self._api_analyzer:

            async def api_part() -> Tuple[list, list, list, list]:
                try:
                    api_findings = await self._wait_for_item(
                        self._api_analyzer.analyze(
                            analysis_content, dict(base_context)
                        ),
                        "API",
                    )
                    for finding in api_findings:
                        finding.analyzer = "API"
                    return api_findings, [AnalyzerEnum.API], [], []
                except Exception as e:
                    errors: List[Dict[str, str]] = []
                    self._record_analyzer_error(errors, "API", "resource_content", e)
                    return [], [], [], errors

            parts.append(api_part)

        if AnalyzerEnum.YARA in analyzers:

            async def yara_part() -> Tuple[list, list, list, list]:
                try:
                    yara_findings = await self._wait_for_item(
                        self._yara_analyzer.analyze(
                            analysis_content,
                            {
                                "resource_uri": resource_uri,
                                "resource_name": resource_name,
                                "content_type": "resource_content",
                            },
                        ),
                        "YARA",
                    )
                    for finding in yara_findings:
                        finding.analyzer = "YARA"
                    return yara_findings, [AnalyzerEnum.YARA], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "YARA", "resource_content", e)
                    return [], [], [], errors

            parts.append(yara_part)

        if AnalyzerEnum.LLM in analyzers and self._llm_analyzer:

            async def llm_part() -> Tuple[list, list, list, list]:
                try:
                    llm_content = f"Resource URI: {resource_uri}\n"
                    llm_content += f"Resource Name: {resource_name}\n"
                    if resource_description:
                        llm_content += f"Description: {resource_description}\n"
                    llm_content += f"MIME Type: {resource_mime_type}\n"
                    llm_content += f"Content:\n{analysis_content[:2000]}\n"
                    llm_context = dict(base_context)
                    llm_context["entity_type"] = "resource"
                    llm_findings = await self._wait_for_item(
                        self._llm_analyzer.analyze(llm_content, llm_context),
                        "LLM",
                    )
                    for finding in llm_findings:
                        finding.analyzer = "LLM"
                    return llm_findings, [AnalyzerEnum.LLM], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(errors, "LLM", "resource_content", e)
                    return [], [], [], errors

            parts.append(llm_part)
        elif AnalyzerEnum.LLM in analyzers and not self._llm_analyzer:
            logger.warning(
                "LLM scan requested for resource '%s' but LLM analyzer not "
                "initialized (MCP_SCANNER_LLM_API_KEY missing)",
                resource_uri,
            )

        if AnalyzerEnum.PROMPT_DEFENSE in analyzers and self._prompt_defense_analyzer:

            async def prompt_defense_part() -> Tuple[list, list, list, list]:
                try:
                    pd_findings = await self._wait_for_item(
                        self._prompt_defense_analyzer.analyze(
                            analysis_content,
                            {
                                "resource_uri": resource_uri,
                                "resource_name": resource_name,
                                "content_type": "resource_content",
                            },
                        ),
                        "PROMPT_DEFENSE",
                    )
                    for finding in pd_findings:
                        finding.analyzer = "PromptDefense"
                    return pd_findings, [AnalyzerEnum.PROMPT_DEFENSE], [], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(
                        errors, "PROMPT_DEFENSE", "resource_content", e
                    )
                    return [], [], [], errors

            parts.append(prompt_defense_part)

        for custom_analyzer in self._custom_analyzers:

            async def custom_part(
                analyzer=custom_analyzer,
            ) -> Tuple[list, list, list, list]:
                try:
                    custom_context = dict(base_context)
                    if http_headers:
                        custom_context["http_headers"] = http_headers
                    findings = await self._wait_for_item(
                        analyzer.analyze(analysis_content, custom_context),
                        "custom analyzer",
                    )
                    for finding in findings:
                        finding.analyzer = analyzer.name
                    return findings, [], [analyzer.name], []
                except Exception as e:
                    errors = []
                    self._record_analyzer_error(
                        errors, analyzer.name, "resource_content", e
                    )
                    return [], [], [], errors

            parts.append(custom_part)

        (
            all_findings,
            successful_analyzers,
            custom_analyzer_names,
            analyzer_errors,
        ) = await self._parallel_analyzer_parts(parts)

        self._record_infrastructure_gaps(
            all_findings, analyzer_errors, "resource_content"
        )
        all_analyzers, status = self._analysis_outcome(
            successful_analyzers, custom_analyzer_names, analyzer_errors
        )

        return ResourceScanResult(
            resource_uri=resource_uri,
            resource_name=resource_name,
            resource_mime_type=resource_mime_type,
            status=status,
            analyzers=all_analyzers,
            findings=all_findings,
            analyzer_errors=analyzer_errors,
            # P0-3 fix: persist the actual content the analyzers consumed
            # so the meta-analyzer (a downstream second-pass FP filter) can
            # second-guess decisions against the same evidence. ``analysis_content``
            # is post-HTML-extraction; that's exactly what API/LLM analyzers
            # received above.
            resource_description=resource_description,
            resource_text=analysis_content,
        )

    def _resource_coverage_limit_result(
        self,
        resource_uri: str,
        resource_name: str,
        resource_mime_type: str,
        error: CoverageLimitExceeded,
    ) -> ResourceScanResult:
        """Failed resource result when a size budget is exceeded.

        Analyzers are not invoked. ``resource_text`` keeps only the bounded
        excerpt, never the unbounded body.
        """
        finding = build_infrastructure_error_finding(
            analyzer_name="MCP",
            subject=resource_name or str(resource_uri),
            error=error,
            context="local",
            safe_reason="coverage_limit",
        )
        return ResourceScanResult(
            resource_uri=resource_uri,
            resource_name=resource_name,
            resource_mime_type=resource_mime_type,
            status="failed",
            analyzers=[],
            findings=[finding],
            resource_text=error.excerpt,
        )

    def _resource_read_failure_result(
        self,
        resource_uri: str,
        resource_name: str,
        resource_mime_type: Optional[str],
        error: Exception,
    ) -> ResourceScanResult:
        """Failed resource result when the body could not be read or analyzed."""
        finding = build_infrastructure_error_finding(
            analyzer_name="MCP",
            subject=resource_name or str(resource_uri),
            error=error,
            context="local",
        )
        return ResourceScanResult(
            resource_uri=resource_uri,
            resource_name=resource_name,
            resource_mime_type=resource_mime_type or "unknown",
            status="failed",
            analyzers=[],
            findings=[finding],
        )

    async def _scan_listed_resources(
        self,
        session: ClientSession,
        resources: Sequence[Any],
        analyzers: List[AnalyzerEnum],
        http_headers: Optional[dict],
        allowed_mime_types: List[str],
        sink: Optional[asyncio.Queue] = None,
    ) -> List[ResourceScanResult]:
        """Read and analyze listed resources in list order.

        Up to the scan limit are read at once. Bytes are committed in list
        order. A read already started can finish, and its body is not scanned
        once an earlier resource has exhausted the budget. Listed MIME types
        that are not allowed are not read and do not consume budget.
        """
        resources = list(resources)
        results: List[Optional[ResourceScanResult]] = [None] * len(resources)
        aggregate_limit = MCPScannerConstants.MAX_PROMPT_RESOURCE_AGGREGATE_CHARS
        remaining = aggregate_limit
        scan_sem = asyncio.Semaphore(self._remote_scan_limit())
        meta_sem = asyncio.Semaphore(self._META_CONCURRENCY)
        finishes: List[asyncio.Task] = []

        def coverage(resource: Any) -> ResourceScanResult:
            resource_mime = self._advertised_resource_mime(resource)
            return self._resource_coverage_limit_result(
                resource.uri,
                resource.name or "",
                self._normalize_mime_type(resource_mime) or "unknown",
                CoverageLimitExceeded(
                    "resource scan aggregate budget exhausted",
                    limit=aggregate_limit,
                ),
            )

        def failed(
            resource: Any, mime: Optional[str], error: Exception
        ) -> ResourceScanResult:
            return self._resource_read_failure_result(
                resource.uri, resource.name or "", mime, error
            )

        def settle(index: int, awaitable: Any, *, bounded: bool = False) -> None:
            async def _finish() -> None:
                async def analyze() -> ResourceScanResult:
                    return await awaitable

                async def meta(result: ResourceScanResult) -> ResourceScanResult:
                    return await self._meta_analyze_one_resource(result, meta_sem)

                use_meta = (
                    AnalyzerEnum.META in analyzers and self._meta_analyzer is not None
                )
                results[index] = await self._analyze_and_meta_item(
                    scan_sem if bounded else None,
                    analyze,
                    meta if use_meta else None,
                )
                if sink is not None and results[index] is not None:
                    await sink.put(results[index])

            finishes.append(asyncio.create_task(_finish()))

        async def ready(result: ResourceScanResult) -> ResourceScanResult:
            return result

        async def read_one(resource: Any) -> Tuple[str, Any]:
            """Read one resource. The scheduled window is the concurrency cap."""
            resource_mime = self._advertised_resource_mime(resource)
            try:
                resource_contents = await asyncio.wait_for(
                    session.read_resource(resource.uri),
                    timeout=MCPScannerConstants.MCP_CONTENT_READ_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                logger.error("Timeout reading resource '%s'", resource.uri)
                return "terminal", failed(
                    resource, resource_mime, asyncio.TimeoutError()
                )
            except Exception as e:
                logger.error(
                    "Error reading resource '%s': %s",
                    resource.uri,
                    type(e).__name__,
                )
                return "terminal", failed(resource, resource_mime, e)

            try:
                (
                    text_content,
                    effective_mime,
                    binary_only,
                    truncated,
                    observed,
                ) = self._extract_resource_read_result(resource_contents, resource_mime)
            except (AttributeError, TypeError) as e:
                logger.warning(
                    "Error extracting content from resource '%s': %s",
                    resource.uri,
                    type(e).__name__,
                )
                return "terminal", failed(resource, resource_mime, e)

            if binary_only or not text_content.strip():
                logger.info(f"No text content found for resource '{resource.uri}'")
                return (
                    "terminal",
                    ResourceScanResult(
                        resource_uri=resource.uri,
                        resource_name=resource.name or "",
                        resource_mime_type=effective_mime,
                        status="skipped",
                        analyzers=[],
                        findings=[],
                    ),
                )

            if not self._resource_mime_is_allowed(effective_mime, allowed_mime_types):
                logger.info(
                    f"Skipping resource '{resource.uri}' with effective "
                    f"MIME type '{effective_mime}'"
                )
                return (
                    "terminal",
                    ResourceScanResult(
                        resource_uri=resource.uri,
                        resource_name=resource.name or "",
                        resource_mime_type=effective_mime,
                        status="skipped",
                        analyzers=[],
                        findings=[],
                    ),
                )

            return "content", (text_content, effective_mime, truncated, observed)

        async def analyze_body(
            resource: Any, text: str, mime: str
        ) -> ResourceScanResult:
            resource_mime = self._advertised_resource_mime(resource)
            try:
                return await self._analyze_resource(
                    text,
                    resource.uri,
                    resource.name or "",
                    getattr(resource, "description", None) or "",
                    mime,
                    analyzers,
                    http_headers,
                )
            except Exception as e:
                logger.error(
                    "Error analyzing resource '%s': %s",
                    resource.uri,
                    type(e).__name__,
                )
                return failed(resource, resource_mime, e)

        read_limit = self._remote_scan_limit()
        scheduled: Dict[int, asyncio.Task] = {}
        skipped: set[int] = set()
        cursor = 0

        def schedule_reads() -> None:
            nonlocal cursor
            while (
                len(scheduled) < read_limit
                and cursor < len(resources)
                and remaining > 0
            ):
                index = cursor
                resource = resources[index]
                cursor += 1
                resource_mime = self._advertised_resource_mime(resource)
                listed_mime = self._normalize_mime_type(resource_mime) or "unknown"
                if resource_mime and not self._resource_mime_is_allowed(
                    listed_mime, allowed_mime_types
                ):
                    logger.info(
                        f"Skipping resource '{resource.uri}' with MIME type "
                        f"'{listed_mime}'"
                    )
                    skipped.add(index)
                    settle(
                        index,
                        ready(
                            ResourceScanResult(
                                resource_uri=resource.uri,
                                resource_name=resource.name or "",
                                resource_mime_type=listed_mime,
                                status="skipped",
                                analyzers=[],
                                findings=[],
                            )
                        ),
                    )
                    continue
                scheduled[index] = asyncio.create_task(read_one(resource))

        async def drop_read(task: asyncio.Task) -> None:
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await task

        try:
            schedule_reads()
            for index, resource in enumerate(resources):
                if index in skipped or results[index] is not None:
                    continue
                task = scheduled.pop(index, None)
                if remaining <= 0:
                    if task is not None:
                        await drop_read(task)
                    settle(index, ready(coverage(resource)))
                    continue
                if task is None:
                    settle(index, ready(coverage(resource)))
                    self._refill_prefetch(schedule_reads, remaining > 0)
                    continue

                kind, payload = await task
                if kind == "terminal":
                    settle(index, ready(payload))
                    self._refill_prefetch(schedule_reads, remaining > 0)
                    continue

                text_content, effective_mime, truncated, observed = payload
                if truncated:
                    limit_error = CoverageLimitExceeded(
                        (
                            f"resource body size {observed} exceeds limit "
                            f"{MCPScannerConstants.MAX_RESOURCE_BODY_CHARS}"
                        ),
                        excerpt=text_content,
                        observed=observed,
                        limit=MCPScannerConstants.MAX_RESOURCE_BODY_CHARS,
                    )
                    settle(
                        index,
                        ready(
                            self._resource_coverage_limit_result(
                                resource.uri,
                                resource.name or "",
                                effective_mime,
                                limit_error,
                            )
                        ),
                    )
                    remaining = self._consume_rejected_budget(
                        observed, text_content, remaining
                    )
                else:
                    bounded, limit_error = self._apply_body_budget(
                        text_content,
                        MCPScannerConstants.MAX_RESOURCE_BODY_CHARS,
                        remaining,
                    )
                    if limit_error is not None:
                        settle(
                            index,
                            ready(
                                self._resource_coverage_limit_result(
                                    resource.uri,
                                    resource.name or "",
                                    effective_mime,
                                    limit_error,
                                )
                            ),
                        )
                        remaining = self._consume_rejected_budget(
                            len(text_content), bounded, remaining
                        )
                    else:
                        remaining -= len(bounded)
                        settle(
                            index,
                            analyze_body(resource, bounded, effective_mime),
                            bounded=True,
                        )
                if remaining <= 0:
                    for pending in scheduled.values():
                        pending.cancel()
                else:
                    self._refill_prefetch(schedule_reads, True)

            for pending in scheduled.values():
                await drop_read(pending)

            if finishes:
                await asyncio.gather(*finishes)
            missing = [index for index, result in enumerate(results) if result is None]
            if missing:
                raise RuntimeError(f"resource scan left indexes unsettled: {missing}")
            return results
        finally:
            await _await_cancelled_tasks([*finishes, *scheduled.values()])

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

        Raises:
            MCPAuthenticationError: If authentication fails (HTTP 401/403).
            MCPServerNotFoundError: If the server endpoint is not found (HTTP 404).
            MCPConnectionError: If unable to connect to the server (network issues, DNS failure, etc).
            ValueError: If the server URL is invalid or empty.
        """
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        # Default: API + YARA (same as tools) plus LLM when configured
        if analyzers is None:
            analyzers = [*self.DEFAULT_ANALYZERS, AnalyzerEnum.LLM]

        # Default allowed MIME types
        if allowed_mime_types is None:
            allowed_mime_types = ["text/plain", "text/html"]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url,
                auth,
                connector_id=connector_id,
                tenant_id=tenant_id,
            )

            # Capability gate: if the InitializeResult didn't advertise
            # resources support, don't bother calling list_resources — many
            # real servers return HTTP 404 for the unsupported method which
            # the MCP SDK relabels as "Session terminated".
            if self._server_supports_capability(session, "resources") is False:
                logger.info(
                    f"Server '{server_url}' did not advertise resources capability; skipping resource scan"
                )
                return []

            # List all resources
            try:
                resources, list_gap = await self._list_mcp_items(
                    session, "resources", server_url
                )
            except McpError as e:
                if self._is_missing_capability_error(e):
                    logger.warning(
                        f"Server '{server_url}' does not expose resources: {e}"
                    )
                    return []
                raise

            results = await self._scan_listed_resources(
                session,
                resources,
                analyzers,
                http_headers,
                allowed_mime_types,
            )
            if list_gap:
                self._append_list_gap(results, "resources", list_gap)
            return results

        except Exception as e:
            logger.error(f"Error scanning resources on server {server_url}: {e}")
            raise
        finally:
            await self._close_mcp_session(client_context, session)

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
        if not server_url:
            raise ValueError(
                "No server URL provided. Please specify a valid server URL."
            )

        if not resource_uri:
            raise ValueError(
                "No resource URI provided. Please specify a valid resource URI."
            )

        # Default: API + YARA (same as tools) plus LLM when configured
        if analyzers is None:
            analyzers = [*self.DEFAULT_ANALYZERS, AnalyzerEnum.LLM]

        # Default allowed MIME types
        if allowed_mime_types is None:
            allowed_mime_types = ["text/plain", "text/html"]

        # Validate that requested analyzers have required configuration
        self._validate_analyzer_requirements(analyzers)

        client_context = None
        session = None
        try:
            client_context, session = await self._get_mcp_session(
                server_url,
                auth,
                connector_id=connector_id,
                tenant_id=tenant_id,
            )

            # Capability gate (same rationale as scan_remote_server_resources).
            if self._server_supports_capability(session, "resources") is False:
                message = f"Server '{server_url}' did not advertise resources capability; cannot scan '{resource_uri}'."
                logger.warning(message)
                raise ValueError(message)

            # List all resources to find the target
            try:
                resources, list_gap = await self._list_mcp_items(
                    session,
                    "resources",
                    server_url,
                    stop_when=lambda resource: str(getattr(resource, "uri", ""))
                    == resource_uri,
                )
            except McpError as e:
                if self._is_missing_capability_error(e):
                    message = f"Server '{server_url}' does not expose resources; cannot scan '{resource_uri}'."
                    logger.warning(message)
                    raise ValueError(message) from e
                raise

            target_resource = None
            for resource in resources:
                # Convert AnyUrl to string for comparison
                resource_uri_str = (
                    str(resource.uri)
                    if hasattr(resource.uri, "__str__")
                    else resource.uri
                )
                if resource_uri_str == resource_uri:
                    target_resource = resource
                    break

            target_resource = self._missing_listed_item(
                target_resource,
                list_gap,
                f"Resource '{resource_uri}' not found on server {server_url}",
            )

            resource_mime = self._advertised_resource_mime(target_resource)

            # Check if MIME type is allowed. The normalized list MIME is
            # the effective type for this early decision.
            listed_mime = self._normalize_mime_type(resource_mime) or "unknown"
            if resource_mime and not self._resource_mime_is_allowed(
                listed_mime, allowed_mime_types
            ):
                logger.info(
                    f"Resource '{resource_uri}' has unsupported MIME type "
                    f"'{listed_mime}'"
                )
                return ResourceScanResult(
                    resource_uri=target_resource.uri,
                    resource_name=target_resource.name or "",
                    resource_mime_type=listed_mime,
                    status="skipped",
                    analyzers=[],
                    findings=[],
                )

            # Read resource content
            try:
                resource_contents = await asyncio.wait_for(
                    session.read_resource(target_resource.uri),
                    timeout=MCPScannerConstants.MCP_CONTENT_READ_TIMEOUT_SECONDS,
                )

                try:
                    (
                        text_content,
                        effective_mime,
                        binary_only,
                        truncated,
                        observed,
                    ) = self._extract_resource_read_result(
                        resource_contents, resource_mime
                    )
                except (AttributeError, TypeError) as e:
                    logger.warning(
                        "Error extracting content from resource '%s': %s",
                        resource_uri,
                        type(e).__name__,
                    )
                    return self._resource_read_failure_result(
                        target_resource.uri,
                        target_resource.name or "",
                        resource_mime,
                        e,
                    )

                if binary_only or not text_content.strip():
                    logger.info(f"No text content found for resource '{resource_uri}'")
                    return ResourceScanResult(
                        resource_uri=target_resource.uri,
                        resource_name=target_resource.name or "",
                        resource_mime_type=effective_mime,
                        status="skipped",
                        analyzers=[],
                        findings=[],
                    )

                if not self._resource_mime_is_allowed(
                    effective_mime, allowed_mime_types
                ):
                    logger.info(
                        f"Resource '{resource_uri}' has unsupported effective "
                        f"MIME type '{effective_mime}'"
                    )
                    return ResourceScanResult(
                        resource_uri=target_resource.uri,
                        resource_name=target_resource.name or "",
                        resource_mime_type=effective_mime,
                        status="skipped",
                        analyzers=[],
                        findings=[],
                    )

                if truncated:
                    return self._resource_coverage_limit_result(
                        target_resource.uri,
                        target_resource.name or "",
                        effective_mime,
                        CoverageLimitExceeded(
                            (
                                f"resource body size {observed} exceeds "
                                f"limit {MCPScannerConstants.MAX_RESOURCE_BODY_CHARS}"
                            ),
                            excerpt=text_content,
                            observed=observed,
                            limit=MCPScannerConstants.MAX_RESOURCE_BODY_CHARS,
                        ),
                    )

                bounded, limit_error = self._apply_body_budget(
                    text_content,
                    MCPScannerConstants.MAX_RESOURCE_BODY_CHARS,
                    MCPScannerConstants.MAX_PROMPT_RESOURCE_AGGREGATE_CHARS,
                )
                if limit_error is not None:
                    return self._resource_coverage_limit_result(
                        target_resource.uri,
                        target_resource.name or "",
                        effective_mime,
                        limit_error,
                    )

                async with self._item_budget_scope():
                    result = await self._analyze_resource(
                        bounded,
                        target_resource.uri,
                        target_resource.name or "",
                        target_resource.description or "",
                        effective_mime,
                        analyzers,
                        http_headers,
                    )
                    result = await self._run_meta_analysis_on_single_resource(
                        result, analyzers
                    )
                return result

            except asyncio.TimeoutError:
                logger.error("Timeout reading resource '%s'", resource_uri)
                return self._resource_read_failure_result(
                    target_resource.uri,
                    target_resource.name or "",
                    resource_mime,
                    asyncio.TimeoutError(),
                )
            except Exception as e:
                logger.error(
                    "Error reading resource '%s': %s",
                    resource_uri,
                    type(e).__name__,
                )
                return self._resource_read_failure_result(
                    target_resource.uri,
                    target_resource.name or "",
                    resource_mime,
                    e,
                )

        except ValueError:
            raise
        except Exception as e:
            logger.error(
                f"Error scanning resource '{resource_uri}' on server {server_url}: {e}"
            )
            raise
        finally:
            await self._close_mcp_session(client_context, session)
