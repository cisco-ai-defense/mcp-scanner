"""Remote scan throughput: bounded concurrency, ordered budgets, list timeouts."""

import asyncio
import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from mcp.types import Prompt as MCPPrompt
from mcp.types import PromptMessage, TextContent

from mcpscanner import Config, Scanner
from mcpscanner.config.constants import CONSTANTS, MCPScannerConstants
from mcpscanner.core.exceptions import MCPConnectionError
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.result import ResourceScanResult, ToolScanResult


@pytest.fixture
def config():
    return Config(api_key="test_api_key")


def test_llm_max_retries_follows_constant(monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "LLM_MAX_RETRIES", 7)
    assert Config().llm_max_retries == 7
    assert Config(llm_max_retries=0).llm_max_retries == 0
    assert CONSTANTS.LLM_MAX_RETRIES == 7


def _patch_session(scanner, session):
    return (
        patch.object(
            scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))
        ),
        patch.object(scanner, "_close_mcp_session", AsyncMock()),
        patch.object(scanner, "_server_supports_capability", return_value=True),
    )


@pytest.mark.asyncio
async def test_resource_analysis_overlaps_the_next_read(config):
    scanner = Scanner(config)
    resources = [
        SimpleNamespace(
            uri=f"resource://r{i}",
            name=f"r{i}",
            description="",
            mimeType="text/plain",
        )
        for i in range(2)
    ]
    order = []

    async def read_resource(uri):
        await asyncio.sleep(0)
        order.append(f"read {uri}")
        return SimpleNamespace(
            contents=[SimpleNamespace(text="hello", mimeType="text/plain", blob=None)]
        )

    async def analyze(text, uri, name, description, mime, analyzers, http_headers=None):
        order.append(f"analyze {uri}")
        return ResourceScanResult(
            resource_uri=uri,
            resource_name=name,
            resource_mime_type=mime,
            status="completed",
            analyzers=[],
            findings=[],
        )

    session = AsyncMock()
    session.list_resources.return_value = SimpleNamespace(resources=resources)
    session.read_resource.side_effect = read_resource
    scanner._analyze_resource = analyze
    patches = _patch_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        results = await scanner.scan_remote_server_resources(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
            allowed_mime_types=["text/plain"],
        )
    assert [result.resource_uri for result in results] == [
        "resource://r0",
        "resource://r1",
    ]
    assert order.index("read resource://r1") < order.index("analyze resource://r0")


@pytest.mark.asyncio
async def test_resource_budget_stays_in_list_order(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "MAX_PROMPT_RESOURCE_AGGREGATE_CHARS", 10)
    monkeypatch.setattr(MCPScannerConstants, "REMOTE_SCAN_CONCURRENCY", 3)
    scanner = Scanner(config)
    bodies = {
        "resource://a": "123456789",
        "resource://b": "12345",
        "resource://c": "12",
    }
    resources = [
        SimpleNamespace(
            uri=uri,
            name=uri.rsplit("/", 1)[-1],
            description="",
            mimeType="text/plain",
        )
        for uri in bodies
    ]

    async def read_resource(uri):
        return SimpleNamespace(
            contents=[
                SimpleNamespace(text=bodies[uri], mimeType="text/plain", blob=None)
            ]
        )

    session = AsyncMock()
    session.list_resources.return_value = SimpleNamespace(resources=resources)
    session.read_resource.side_effect = read_resource

    async def analyze(text, uri, name, description, mime, analyzers, http_headers=None):
        return ResourceScanResult(
            resource_uri=uri,
            resource_name=name,
            resource_mime_type=mime,
            status="completed",
            analyzers=[],
            findings=[],
            resource_text=text,
        )

    scanner._analyze_resource = analyze
    patches = _patch_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        results = await scanner.scan_remote_server_resources(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
            allowed_mime_types=["text/plain"],
        )
    assert [result.resource_uri for result in results] == list(bodies)
    assert results[0].status == "completed"
    assert results[0].resource_text == "123456789"
    assert results[1].status == "failed"
    assert results[2].status == "failed"
    assert "Coverage" in results[1].findings[0].summary
    assert "budget" in results[2].findings[0].summary
    assert results[1].resource_text != "12345"
    assert session.read_resource.await_count == 3


@pytest.mark.asyncio
async def test_prompt_analysis_overlaps_the_next_fetch(config):
    scanner = Scanner(config)
    prompts = [MCPPrompt(name=f"p{i}", description="d", arguments=[]) for i in range(2)]
    order = []

    async def get_prompt(name, arguments=None):
        await asyncio.sleep(0)
        order.append(f"fetch {name}")
        return SimpleNamespace(
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(type="text", text="ok"),
                )
            ]
        )

    async def analyze(prompt, analyzers, http_headers=None, prompt_messages_text=""):
        order.append(f"analyze {prompt.name}")
        return SimpleNamespace(status="completed", findings=[], prompt_name=prompt.name)

    session = AsyncMock()
    session.list_prompts.return_value = SimpleNamespace(prompts=prompts)
    session.get_prompt.side_effect = get_prompt
    scanner._analyze_prompt = analyze
    patches = _patch_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        await scanner.scan_remote_server_prompts(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
        )
    assert order.index("fetch p1") < order.index("analyze p0")


@pytest.mark.asyncio
async def test_list_resources_timeout(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "MCP_LIST_TIMEOUT_SECONDS", 0.05)
    scanner = Scanner(config)

    async def list_resources():
        await asyncio.sleep(2)

    session = AsyncMock()
    session.list_resources = list_resources
    patches = _patch_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        with pytest.raises(MCPConnectionError, match="resources/list"):
            await scanner.scan_remote_server_resources(
                "https://example.com/mcp",
                analyzers=[AnalyzerEnum.YARA],
            )


@pytest.mark.asyncio
async def test_tool_analysis_is_bounded(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "REMOTE_SCAN_CONCURRENCY", 2)
    scanner = Scanner(config)
    tools = [SimpleNamespace(name=f"t{i}", description="d") for i in range(3)]
    current = 0
    peak = 0
    started = 0
    release = asyncio.Event()

    async def analyze_tool(tool, analyzers, http_headers=None):
        nonlocal current, peak, started
        current += 1
        started += 1
        peak = max(peak, current)
        if started >= 2:
            release.set()
        try:
            await release.wait()
        finally:
            current -= 1
        return ToolScanResult(
            tool_name=tool.name,
            tool_description=tool.description,
            status="completed",
            analyzers=[],
            findings=[],
        )

    scanner._analyze_tool = analyze_tool
    results = await asyncio.wait_for(
        scanner._analyze_tools_bounded(tools, [AnalyzerEnum.YARA]),
        timeout=2,
    )
    assert peak == 2
    assert [result.tool_name for result in results] == ["t0", "t1", "t2"]


@pytest.mark.asyncio
async def test_analyzer_deadline_keeps_earlier_findings(config, monkeypatch):
    from mcp.types import Tool

    from mcpscanner.core.analyzers.base import SecurityFinding

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.05)
    scanner = Scanner(config)
    finding = SecurityFinding(
        severity="HIGH",
        summary="yara matched",
        analyzer="YARA",
        threat_category="PROMPT INJECTION",
    )

    async def yara_analyze(*_args, **_kwargs):
        return [finding]

    async def slow_custom(*_args, **_kwargs):
        await asyncio.sleep(1)
        return []

    scanner._yara_analyzer = SimpleNamespace(analyze=yara_analyze)
    scanner._custom_analyzers = [
        SimpleNamespace(name="slow-custom", analyze=slow_custom)
    ]
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.YARA])
    assert result.status == "partial"
    assert result.findings
    assert result.findings[0].summary == "yara matched"
    assert result.is_safe is False
    assert any(error["analyzer"] == "slow-custom" for error in result.analyzer_errors)


@pytest.mark.asyncio
async def test_session_connect_timeout(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "MCP_SESSION_TIMEOUT_SECONDS", 0.05)

    class SlowContext:
        async def __aenter__(self):
            await asyncio.sleep(2)
            return (None, None)

        async def __aexit__(self, *_args):
            return False

    scanner = Scanner(config)
    with patch(
        "mcpscanner.core.scanner.streamable_http_client",
        return_value=SlowContext(),
    ), patch(
        "mcpscanner.core.scanner.create_mcp_http_client",
        return_value=AsyncMock(),
    ):
        with pytest.raises(MCPConnectionError, match="Timed out connecting"):
            await scanner._get_mcp_session("https://example.com/mcp")


@pytest.mark.asyncio
async def test_explicit_rpc_timeout_overrides_list_default(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "MCP_LIST_TIMEOUT_SECONDS", 0.01)
    scanner = Scanner(config)

    async def slow():
        await asyncio.sleep(0.05)
        return "listed"

    assert await scanner._await_mcp_rpc(slow(), "tools/list", "cmd", timeout=1) == (
        "listed"
    )


@pytest.mark.asyncio
async def test_llm_request_gate_limits_concurrency(monkeypatch):
    import mcpscanner.utils.llm_gate as gate

    monkeypatch.setattr(MCPScannerConstants, "LLM_REQUEST_CONCURRENCY", 1)
    gate._gate = None
    gate._loop = None
    sem = gate.llm_request_gate()
    assert sem._value == 1
    entered = 0
    peak = 0
    release = asyncio.Event()

    async def holder():
        nonlocal entered, peak
        async with sem:
            entered += 1
            peak = max(peak, entered)
            await release.wait()
            entered -= 1

    first = asyncio.create_task(holder())
    await asyncio.sleep(0)
    second = asyncio.create_task(holder())
    await asyncio.sleep(0)
    assert peak == 1
    release.set()
    await asyncio.gather(first, second)
    gate._gate = None
    gate._loop = None


def test_remote_timeouts_allow_a_slow_catalog():
    if os.getenv("MCP_SCANNER_MCP_LIST_TIMEOUT_SECONDS") is None:
        assert MCPScannerConstants.MCP_LIST_TIMEOUT_SECONDS == 120
    if os.getenv("MCP_SCANNER_MCP_SESSION_TIMEOUT_SECONDS") is None:
        assert MCPScannerConstants.MCP_SESSION_TIMEOUT_SECONDS == 60
    if os.getenv("MCP_SCANNER_MCP_CONTENT_READ_TIMEOUT_SECONDS") is None:
        assert MCPScannerConstants.MCP_CONTENT_READ_TIMEOUT_SECONDS == 120


@pytest.mark.asyncio
async def test_item_deadline_is_shared_across_analyzer_calls(config, monkeypatch):
    from mcp.types import Tool

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.2)
    scanner = Scanner(config)

    async def slow(*_args, **_kwargs):
        await asyncio.sleep(0.15)
        return []

    scanner._api_analyzer = SimpleNamespace(analyze=slow)
    scanner._custom_analyzers = [SimpleNamespace(name="extra", analyze=slow)]
    tool = Tool(
        name="risky", description="do the thing", inputSchema={"type": "object"}
    )
    started = time.monotonic()
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.API])
    elapsed = time.monotonic() - started
    assert elapsed < 0.35
    assert not any(error["analyzer"] == "extra" for error in result.analyzer_errors)
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_slot_wait_does_not_consume_the_item_deadline(config, monkeypatch):
    from mcp.types import Tool

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.4)
    monkeypatch.setattr(MCPScannerConstants, "REMOTE_SCAN_CONCURRENCY", 1)
    scanner = Scanner(config)
    scanner._config._llm_timeout = 0.05
    scanner._config._llm_max_retries = 0
    scanner._config._llm_rate_limit_delay = 0

    async def llm_for_tool(*_args, **_kwargs):
        await asyncio.sleep(0.25)
        return []

    scanner._llm_analyzer = SimpleNamespace(analyze=llm_for_tool)
    tools = [
        Tool(name="t0", description="d", inputSchema={"type": "object"}),
        Tool(name="t1", description="d", inputSchema={"type": "object"}),
    ]
    results = await scanner._analyze_tools_bounded(tools, [AnalyzerEnum.LLM])
    assert [result.status for result in results] == ["completed", "completed"]
    assert all(not result.analyzer_errors for result in results)


@pytest.mark.asyncio
async def test_meta_stops_at_the_same_item_deadline(config, monkeypatch):
    from mcp.types import Tool

    from mcpscanner.core.analyzers.base import SecurityFinding

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.05)
    scanner = Scanner(config)
    scanner._config._llm_timeout = 0
    scanner._config._llm_max_retries = 0
    scanner._config._llm_rate_limit_delay = 0
    finding = SecurityFinding(
        severity="HIGH",
        summary="yara matched",
        analyzer="YARA",
        threat_category="PROMPT INJECTION",
    )

    async def yara_analyze(*_args, **_kwargs):
        return [finding]

    async def slow_custom(*_args, **_kwargs):
        await asyncio.sleep(1)
        return []

    async def slow_meta(*_args, **_kwargs):
        await asyncio.sleep(1)
        return {}

    scanner._yara_analyzer = SimpleNamespace(analyze=yara_analyze)
    scanner._custom_analyzers = [
        SimpleNamespace(name="slow-custom", analyze=slow_custom)
    ]
    scanner._meta_analyzer = SimpleNamespace(analyze_findings=slow_meta)
    tool = Tool(
        name="risky", description="do the thing", inputSchema={"type": "object"}
    )
    started = time.monotonic()
    result = await scanner._analyze_tool_for_scan(
        tool,
        [AnalyzerEnum.YARA, AnalyzerEnum.META],
        None,
        asyncio.Semaphore(1),
        asyncio.Semaphore(1),
    )
    assert time.monotonic() - started < 0.4
    assert result.findings[0].summary == "yara matched"
    assert result.status == "partial"
    assert any(error["analyzer"] == "META" for error in result.analyzer_errors)
    assert result.is_safe is False


@pytest.mark.asyncio
async def test_prompt_and_resource_deadlines_keep_earlier_findings(
    config, monkeypatch
):
    from mcpscanner.core.analyzers.base import SecurityFinding

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.05)
    scanner = Scanner(config)
    finding = SecurityFinding(
        severity="HIGH",
        summary="yara matched",
        analyzer="YARA",
        threat_category="PROMPT INJECTION",
    )

    async def yara_analyze(*_args, **_kwargs):
        return [finding]

    async def slow_custom(*_args, **_kwargs):
        await asyncio.sleep(1)
        return []

    scanner._yara_analyzer = SimpleNamespace(analyze=yara_analyze)
    scanner._custom_analyzers = [
        SimpleNamespace(name="slow-custom", analyze=slow_custom)
    ]
    prompt = MCPPrompt(name="p", description="d", arguments=[])
    prompt_result = await scanner._analyze_prompt(
        prompt,
        [AnalyzerEnum.YARA],
        prompt_messages_text="body",
    )
    assert prompt_result.status == "partial"
    assert prompt_result.findings[0].summary == "yara matched"
    assert prompt_result.is_safe is False

    resource_result = await scanner._analyze_resource(
        "hello",
        "resource://r",
        "r",
        "",
        "text/plain",
        [AnalyzerEnum.YARA],
    )
    assert resource_result.status == "partial"
    assert resource_result.findings[0].summary == "yara matched"
    assert resource_result.is_safe is False


@pytest.mark.asyncio
async def test_prompt_fetch_failure_runs_meta(config):
    scanner = Scanner(config)
    seen = []

    async def fake_meta(result, sem):
        seen.append(result.prompt_name)
        return result

    scanner._meta_analyzer = object()
    scanner._meta_analyze_one_prompt = fake_meta
    prompt = MCPPrompt(name="x", description="d", arguments=[])
    results = await scanner._analyze_collected_prompts(
        [(prompt, "", RuntimeError("nope"))],
        [AnalyzerEnum.YARA, AnalyzerEnum.META],
    )
    assert seen == ["x"]
    assert results[0].status == "failed"


@pytest.mark.asyncio
async def test_llm_gate_limit_stays_fixed_for_the_loop(monkeypatch):
    import mcpscanner.utils.llm_gate as gate

    monkeypatch.setattr(MCPScannerConstants, "LLM_REQUEST_CONCURRENCY", 1)
    gate._gate = None
    gate._loop = None
    first = gate.llm_request_gate()
    monkeypatch.setattr(MCPScannerConstants, "LLM_REQUEST_CONCURRENCY", 4)
    assert gate.llm_request_gate() is first
    assert first._value == 1
    gate._gate = None
    gate._loop = None


@pytest.mark.asyncio
async def test_llm_retry_budget_is_not_cut_by_the_item_deadline(config, monkeypatch):
    from mcp.types import Tool

    from mcpscanner.core.analyzers.base import SecurityFinding

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.05)
    scanner = Scanner(config)
    scanner._config._llm_timeout = 1
    scanner._config._llm_max_retries = 0
    scanner._config._llm_rate_limit_delay = 0
    finding = SecurityFinding(
        severity="HIGH",
        summary="llm matched",
        analyzer="LLM",
        threat_category="PROMPT INJECTION",
    )

    async def llm_analyze(*_args, **_kwargs):
        await asyncio.sleep(0.2)
        return [finding]

    scanner._llm_analyzer = SimpleNamespace(analyze=llm_analyze)
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.LLM])
    assert result.status == "completed"
    assert result.findings[0].summary == "llm matched"
    assert result.analyzer_errors == []


@pytest.mark.asyncio
async def test_fast_analyzer_survives_a_slow_one(config, monkeypatch):
    from mcp.types import Tool

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.05)
    scanner = Scanner(config)
    started = []

    async def slow_api(*_args, **_kwargs):
        started.append("api")
        await asyncio.sleep(1)
        return []

    async def yara_analyze(*_args, **_kwargs):
        started.append("yara")
        return []

    scanner._api_analyzer = SimpleNamespace(analyze=slow_api)
    scanner._yara_analyzer = SimpleNamespace(analyze=yara_analyze)
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.API, AnalyzerEnum.YARA])
    assert started == ["api", "yara"] or set(started) == {"api", "yara"}
    assert result.status == "partial"
    assert any(error["analyzer"] == "API" for error in result.analyzer_errors)
    assert not any(error["analyzer"] == "YARA" for error in result.analyzer_errors)


@pytest.mark.asyncio
async def test_stdio_list_uses_the_stdio_timeout(config):
    from mcpscanner.core.mcp_models import StdioServer

    scanner = Scanner(config)
    seen = {}

    async def fake_rpc(awaitable, operation, target, timeout=None):
        seen["operation"] = operation
        seen["timeout"] = timeout
        close = getattr(awaitable, "close", None)
        if callable(close):
            close()
        return SimpleNamespace(tools=[])

    async def get_session(*_args, **_kwargs):
        return AsyncMock(), AsyncMock()

    scanner._get_stdio_session = get_session
    scanner._close_mcp_session = AsyncMock()
    scanner._await_mcp_rpc = fake_rpc
    results = await scanner.scan_stdio_server_tools(
        StdioServer(command="echo"),
        analyzers=[AnalyzerEnum.YARA],
        timeout=42,
    )
    assert results == []
    assert seen == {"operation": "tools/list", "timeout": 42}


@pytest.mark.asyncio
async def test_resource_read_uses_the_content_timeout(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "MCP_CONTENT_READ_TIMEOUT_SECONDS", 0.2)
    scanner = Scanner(config)
    resource = SimpleNamespace(
        uri="resource://slow",
        name="slow",
        description="",
        mimeType="text/plain",
    )

    async def read_resource(_uri):
        await asyncio.sleep(0.05)
        return SimpleNamespace(
            contents=[SimpleNamespace(text="hello", mimeType="text/plain", blob=None)]
        )

    async def analyze(text, uri, name, description, mime, analyzers, http_headers=None):
        return ResourceScanResult(
            resource_uri=uri,
            resource_name=name,
            resource_mime_type=mime,
            status="completed",
            analyzers=[],
            findings=[],
            resource_text=text,
        )

    session = AsyncMock()
    session.list_resources.return_value = SimpleNamespace(resources=[resource])
    session.read_resource.side_effect = read_resource
    scanner._analyze_resource = analyze
    patches = _patch_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        results = await scanner.scan_remote_server_resources(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
            allowed_mime_types=["text/plain"],
        )
    assert results[0].status == "completed"
    assert results[0].resource_text == "hello"


def test_llm_call_allowance_includes_empty_followups(config):
    scanner = Scanner(config)
    scanner._config._llm_timeout = 30
    scanner._config._llm_max_retries = 3
    scanner._config._llm_rate_limit_delay = 1
    # Transport: 4 * 30 + backoff 1 + 2 + 4. Empty follow-ups: 3 * 30 + 3 * 1.
    assert scanner._llm_call_allowance() == 220


@pytest.mark.asyncio
async def test_fast_readiness_survives_a_slow_llm_call(
    config, monkeypatch
):
    from mcp.types import Tool

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.3)
    scanner = Scanner(config)
    scanner._config._llm_timeout = 0.2
    scanner._config._llm_max_retries = 0
    scanner._config._llm_rate_limit_delay = 0

    async def llm_analyze(*_args, **_kwargs):
        await asyncio.sleep(1)
        return []

    async def judge_findings(*_args, **_kwargs):
        await asyncio.sleep(0.05)
        return []

    scanner._llm_analyzer = SimpleNamespace(analyze=llm_analyze)
    scanner._readiness_analyzer = SimpleNamespace(
        heuristic_findings=lambda *_args, **_kwargs: [],
        opa_enabled=False,
        llm_judge_available=True,
        judge_findings=judge_findings,
        stamp_readiness=lambda findings: list(findings),
    )
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    started = time.monotonic()
    result = await scanner._analyze_tool(
        tool, [AnalyzerEnum.LLM, AnalyzerEnum.READINESS]
    )
    elapsed = time.monotonic() - started
    assert any(error["analyzer"] == "LLM" for error in result.analyzer_errors)
    assert not any(error["analyzer"] == "READINESS" for error in result.analyzer_errors)
    assert elapsed < 0.45


@pytest.mark.asyncio
async def test_prompt_defense_stays_on_the_item_deadline(config, monkeypatch):
    from mcp.types import Tool

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.05)
    scanner = Scanner(config)

    async def slow(*_args, **_kwargs):
        await asyncio.sleep(0.2)
        return []

    scanner._prompt_defense_analyzer = SimpleNamespace(analyze=slow)
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    started = time.monotonic()
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.PROMPT_DEFENSE])
    elapsed = time.monotonic() - started
    assert any(error["analyzer"] == "PROMPT_DEFENSE" for error in result.analyzer_errors)
    assert elapsed < 0.3


@pytest.mark.asyncio
async def test_readiness_heuristics_survive_a_cancelled_judge(config, monkeypatch):
    from mcp.types import Tool

    from mcpscanner.core.analyzers.base import SecurityFinding

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.05)
    scanner = Scanner(config)
    scanner._config._llm_timeout = 0
    scanner._config._llm_max_retries = 0
    scanner._config._llm_rate_limit_delay = 0
    finding = SecurityFinding(
        severity="HIGH",
        summary="missing timeout",
        analyzer="READINESS",
        threat_category="READINESS",
    )

    async def judge_findings(*_args, **_kwargs):
        await asyncio.sleep(1)
        return []

    scanner._readiness_analyzer = SimpleNamespace(
        heuristic_findings=lambda *_args, **_kwargs: [finding],
        opa_enabled=False,
        llm_judge_available=True,
        judge_findings=judge_findings,
        stamp_readiness=lambda findings: list(findings),
    )
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.READINESS])
    assert result.status == "partial"
    assert result.findings[0].summary == "missing timeout"
    assert any(error["analyzer"] == "READINESS" for error in result.analyzer_errors)


@pytest.mark.asyncio
async def test_missing_description_does_not_fail_the_tool_scan(config):
    from mcp.types import Tool

    scanner = Scanner(config)
    tool = Tool(name="bare", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.READINESS])
    assert result.status == "completed"
    assert result.analyzer_errors == []
    assert any("description" in finding.summary.lower() for finding in result.findings)


@pytest.mark.asyncio
async def test_readiness_failure_keeps_earlier_findings(config):
    from mcp.types import Tool

    from mcpscanner.core.analyzers.base import SecurityFinding

    scanner = Scanner(config)
    finding = SecurityFinding(
        severity="HIGH",
        summary="yara matched",
        analyzer="YARA",
        threat_category="PROMPT INJECTION",
    )

    async def yara_analyze(*_args, **_kwargs):
        return [finding]

    def boom(*_args, **_kwargs):
        raise RuntimeError("bad tool")

    scanner._yara_analyzer = SimpleNamespace(analyze=yara_analyze)
    scanner._readiness_analyzer = SimpleNamespace(
        heuristic_findings=boom,
        opa_enabled=False,
        llm_judge_available=False,
        stamp_readiness=lambda findings: list(findings),
    )
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(
        tool, [AnalyzerEnum.YARA, AnalyzerEnum.READINESS]
    )
    assert result.status == "partial"
    assert result.findings[0].summary == "yara matched"
    assert any(error["analyzer"] == "READINESS" for error in result.analyzer_errors)


@pytest.mark.asyncio
async def test_opa_findings_survive_a_cancelled_judge(config, monkeypatch):
    from mcp.types import Tool

    from mcpscanner.core.analyzers.base import SecurityFinding

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.05)
    scanner = Scanner(config)
    scanner._config._llm_timeout = 0
    scanner._config._llm_max_retries = 0
    scanner._config._llm_rate_limit_delay = 0
    opa_finding = SecurityFinding(
        severity="MEDIUM",
        summary="opa policy",
        analyzer="READINESS",
        threat_category="READINESS",
    )

    async def opa_findings(*_args, **_kwargs):
        return [opa_finding]

    async def judge_findings(*_args, **_kwargs):
        await asyncio.sleep(1)
        return []

    scanner._readiness_analyzer = SimpleNamespace(
        heuristic_findings=lambda *_args, **_kwargs: [],
        opa_enabled=True,
        opa_findings=opa_findings,
        llm_judge_available=True,
        judge_findings=judge_findings,
        stamp_readiness=lambda findings: list(findings),
    )
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.READINESS])
    assert result.status == "partial"
    assert result.findings[0].summary == "opa policy"
    assert any(error["analyzer"] == "READINESS" for error in result.analyzer_errors)


@pytest.mark.asyncio
async def test_failed_readiness_judge_stays_incomplete(config):
    from mcp.types import Tool

    scanner = Scanner(config)

    async def judge_findings(*_args, **_kwargs):
        raise RuntimeError("provider down secret")

    scanner._readiness_analyzer = SimpleNamespace(
        heuristic_findings=lambda *_args, **_kwargs: [],
        opa_enabled=False,
        llm_judge_available=True,
        judge_findings=judge_findings,
        stamp_readiness=lambda findings: list(findings),
    )
    tool = Tool(
        name="plain",
        description="An ordinary tool with a clear single purpose",
        inputSchema={"type": "object"},
    )
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.READINESS])
    messages = " ".join(error.get("message", "") for error in result.analyzer_errors)
    assert result.status == "failed"
    assert result.is_safe is None
    assert result.findings == []
    assert "RuntimeError" in messages
    assert "provider down secret" not in messages


@pytest.mark.asyncio
async def test_disabled_judge_leaves_the_llm_extension_for_meta(config, monkeypatch):
    from mcp.types import Tool

    from mcpscanner.core.analyzers.base import SecurityFinding
    from mcpscanner.core.analyzers.meta_analyzer import MetaAnalysisResult

    monkeypatch.setattr(MCPScannerConstants, "ITEM_DEADLINE_SECONDS", 0.1)
    scanner = Scanner(config)
    scanner._config._llm_timeout = 0.5
    scanner._config._llm_max_retries = 0
    scanner._config._llm_rate_limit_delay = 0
    finding = SecurityFinding(
        severity="HIGH",
        summary="missing timeout",
        analyzer="READINESS",
        threat_category="READINESS",
    )

    async def analyze_findings(**_kwargs):
        await asyncio.sleep(0.2)
        return MetaAnalysisResult()

    scanner._readiness_analyzer = SimpleNamespace(
        heuristic_findings=lambda *_args, **_kwargs: [finding],
        opa_enabled=False,
        llm_judge_available=False,
        stamp_readiness=lambda findings: list(findings),
    )
    scanner._meta_analyzer = SimpleNamespace(analyze_findings=analyze_findings)
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})

    async def analyze():
        return await scanner._analyze_tool(tool, [AnalyzerEnum.READINESS])

    async def finish(result):
        return await scanner._meta_analyze_one_tool(result, asyncio.Semaphore(1))

    result = await scanner._analyze_and_meta_item(None, analyze, finish)
    assert result.findings[0].summary == "missing timeout"
    assert not any(error["analyzer"] == "META" for error in result.analyzer_errors)


@pytest.mark.asyncio
async def test_yara_parameter_scan_keeps_the_description_for_readiness(config):
    from mcp.types import Tool

    scanner = Scanner(config)
    seen = []

    async def yara_analyze(content, context):
        seen.append(context.get("content_type"))
        if context.get("content_type") == "parameters":
            assert "destroy all files" not in content
        return []

    scanner._yara_analyzer = SimpleNamespace(analyze=yara_analyze)
    tool = Tool(
        name="wipe",
        description="Delete and destroy all files, then drop the database.",
        inputSchema={"type": "object"},
    )
    result = await scanner._analyze_tool(
        tool, [AnalyzerEnum.YARA, AnalyzerEnum.READINESS]
    )
    rule_ids = {
        (finding.details or {}).get("rule_id")
        for finding in result.findings
        if finding.analyzer == "READINESS"
    }
    assert seen == ["description", "parameters"]
    assert "HEUR-009" not in rule_ids
    assert {"HEUR-010", "HEUR-016", "HEUR-017"} <= rule_ids
    assert result.analyzer_errors == []


@pytest.mark.asyncio
async def test_failed_readiness_check_is_recorded_and_other_findings_stay(config):
    from mcp.types import Tool

    scanner = Scanner(config)

    def boom(_tool_def, _tool_name):
        raise RuntimeError("bad check")

    scanner._readiness_analyzer._check_timeout_too_long = boom
    tool = Tool(name="bare", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.READINESS])
    rule_ids = {
        (finding.details or {}).get("rule_id")
        for finding in result.findings
        if finding.analyzer == "READINESS"
    }
    assert "HEUR-001" in rule_ids
    assert "HEUR-009" in rule_ids
    assert "HEUR-INCOMPLETE" in rule_ids
    incomplete = next(
        finding
        for finding in result.findings
        if (finding.details or {}).get("rule_id") == "HEUR-INCOMPLETE"
    )
    assert incomplete.severity == "MEDIUM"
    assert result.status == "partial"
    readiness_findings = [
        finding for finding in result.findings if finding.analyzer == "READINESS"
    ]
    assert all(
        finding.details.get("is_production_ready") is False
        for finding in readiness_findings
    )
    assert all(
        finding.details.get("readiness_score") is None for finding in readiness_findings
    )
    assert all(
        finding.details.get("failed_checks") == ["HEUR-002"]
        for finding in readiness_findings
    )
    assert any(
        error["message"] == "ReadinessCheckFailure during analysis (HEUR-002)"
        for error in result.analyzer_errors
    )
    assert all(
        "bad check" not in error["message"] for error in result.analyzer_errors
    )


@pytest.mark.asyncio
async def test_tool_list_follows_every_page(config):
    from mcp.types import Tool

    scanner = Scanner(config)
    first = Tool(name="one", description="a", inputSchema={"type": "object"})
    second = Tool(name="two", description="b", inputSchema={"type": "object"})
    session = AsyncMock()
    session.list_tools = AsyncMock(
        side_effect=[
            SimpleNamespace(tools=[first], next_cursor="page-2"),
            SimpleNamespace(tools=[second], next_cursor=None),
        ]
    )
    scanner._analyze_tools_bounded = AsyncMock(return_value=[])
    opened = patch.object(
        scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))
    )
    closed = patch.object(scanner, "_close_mcp_session", AsyncMock())
    with opened, closed:
        await scanner.scan_remote_server_tools(
            "https://example.com/mcp", analyzers=[AnalyzerEnum.YARA]
        )
    listed = scanner._analyze_tools_bounded.await_args.args[0]
    assert [tool.name for tool in listed] == ["one", "two"]
    assert session.list_tools.await_count == 2


@pytest.mark.asyncio
async def test_repeated_list_cursor_does_not_look_complete(config):
    scanner = Scanner(config)
    session = AsyncMock()
    session.list_tools = AsyncMock(
        return_value=SimpleNamespace(tools=[], next_cursor="again")
    )
    opened = patch.object(
        scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))
    )
    closed = patch.object(scanner, "_close_mcp_session", AsyncMock())
    with opened, closed:
        with pytest.raises(MCPConnectionError, match="pagination cursor"):
            await scanner.scan_remote_server_tools(
                "https://example.com/mcp", analyzers=[AnalyzerEnum.YARA]
            )


@pytest.mark.asyncio
async def test_later_list_page_keeps_tools_already_read(config):
    from mcp.types import Tool

    scanner = Scanner(config)
    kept = Tool(name="kept", description="a", inputSchema={"type": "object"})
    also = Tool(name="also", description="b", inputSchema={"type": "object"})
    session = AsyncMock()
    session.list_tools = AsyncMock(
        side_effect=[
            SimpleNamespace(tools=[kept], next_cursor="page-2"),
            SimpleNamespace(tools=[also], next_cursor="page-2"),
        ]
    )
    scanned = ToolScanResult(
        tool_name="kept",
        tool_description="a",
        status="completed",
        analyzers=[AnalyzerEnum.YARA],
        findings=[],
    )
    scanner._analyze_tools_bounded = AsyncMock(return_value=[scanned])
    opened = patch.object(
        scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))
    )
    closed = patch.object(scanner, "_close_mcp_session", AsyncMock())
    with opened, closed:
        results = await scanner.scan_remote_server_tools(
            "https://example.com/mcp", analyzers=[AnalyzerEnum.YARA]
        )
    assert results[0] is scanned
    assert results[0].is_safe is True
    assert results[1].tool_name == "(tools/list)"
    assert results[1].is_safe is None
    assert "pagination cursor" in results[1].findings[0].summary
    assert "pagination cursor" in results[1].analyzer_errors[0]["message"]
    listed = scanner._analyze_tools_bounded.await_args.args[0]
    assert [tool.name for tool in listed] == ["kept", "also"]


@pytest.mark.asyncio
async def test_list_pages_share_one_deadline(config, monkeypatch):
    from mcp.types import Tool

    monkeypatch.setattr(MCPScannerConstants, "MCP_LIST_TIMEOUT_SECONDS", 0.3)
    scanner = Scanner(config)
    kept = Tool(name="kept", description="a", inputSchema={"type": "object"})
    calls = {"n": 0}

    async def list_tools(params=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(tools=[kept], next_cursor="page-2")
        await asyncio.sleep(2)
        return SimpleNamespace(tools=[], next_cursor=None)

    session = AsyncMock()
    session.list_tools = list_tools
    scanner._analyze_tools_bounded = AsyncMock(
        return_value=[
            ToolScanResult(
                tool_name="kept",
                tool_description="a",
                status="completed",
                analyzers=[AnalyzerEnum.YARA],
                findings=[],
            )
        ]
    )
    opened = patch.object(
        scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))
    )
    closed = patch.object(scanner, "_close_mcp_session", AsyncMock())
    started = time.monotonic()
    with opened, closed:
        results = await scanner.scan_remote_server_tools(
            "https://example.com/mcp", analyzers=[AnalyzerEnum.YARA]
        )
    assert time.monotonic() - started < 1
    assert calls["n"] == 2
    assert results[0].tool_name == "kept"
    assert results[1].is_safe is None
    assert "list deadline" in results[1].findings[0].summary


@pytest.mark.asyncio
async def test_named_tool_on_the_first_page_is_scanned(config):
    from mcp.types import Tool

    scanner = Scanner(config)
    wanted = Tool(name="wanted", description="a", inputSchema={"type": "object"})
    calls = {"n": 0}

    async def list_tools(params=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(tools=[wanted], next_cursor="page-2")
        await asyncio.sleep(2)
        return SimpleNamespace(tools=[], next_cursor=None)

    session = AsyncMock()
    session.list_tools = list_tools
    found = ToolScanResult(
        tool_name="wanted",
        tool_description="a",
        status="completed",
        analyzers=[AnalyzerEnum.YARA],
        findings=[],
    )
    scanner._analyze_tool = AsyncMock(return_value=found)
    scanner._run_meta_analysis_on_single_tool = AsyncMock(
        side_effect=lambda result, analyzers: result
    )
    opened = patch.object(
        scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))
    )
    closed = patch.object(scanner, "_close_mcp_session", AsyncMock())
    started = time.monotonic()
    with opened, closed:
        result = await scanner.scan_remote_server_tool(
            "https://example.com/mcp",
            "wanted",
            analyzers=[AnalyzerEnum.YARA],
        )
    assert time.monotonic() - started < 1
    assert calls["n"] == 1
    assert result is found


@pytest.mark.asyncio
async def test_named_tool_is_not_marked_missing_when_the_list_stops(config):
    from mcp.types import Tool

    scanner = Scanner(config)
    other = Tool(name="other", description="a", inputSchema={"type": "object"})
    session = AsyncMock()
    session.list_tools = AsyncMock(
        side_effect=[
            SimpleNamespace(tools=[other], next_cursor="page-2"),
            SimpleNamespace(tools=[other], next_cursor="page-2"),
        ]
    )
    opened = patch.object(
        scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))
    )
    closed = patch.object(scanner, "_close_mcp_session", AsyncMock())
    with opened, closed:
        with pytest.raises(MCPConnectionError, match="pagination cursor"):
            await scanner.scan_remote_server_tool(
                "https://example.com/mcp",
                "wanted",
                analyzers=[AnalyzerEnum.YARA],
            )


@pytest.mark.asyncio
async def test_list_gap_reason_survives_api_and_reports(config):
    import json

    from mcpscanner.api.router import _group_findings_for_api
    from mcpscanner.core.models import OutputFormat, SeverityFilter
    from mcpscanner.core.report_generator import ReportGenerator, results_to_json
    from mcpscanner.core.result import format_results_as_json

    scanner = Scanner(config)
    gap = scanner._append_list_gap(
        [], "tools", "a pagination cursor was repeated"
    )[0]
    reason = "pagination cursor"

    payload = json.loads(format_results_as_json([gap]))["scan_results"][0]
    assert payload["is_safe"] is None
    assert reason in payload["findings"]["mcp_analyzer"]["threat_summary"]
    assert payload["findings"]["mcp_analyzer"]["severity"] == "INFO"
    assert reason in payload["analyzer_errors"][0]["message"]

    api_findings = _group_findings_for_api(gap, scanner)
    assert reason in api_findings["mcp_analyzer"]["threat_summary"]
    assert api_findings["mcp_analyzer"]["severity"] == "INFO"

    reported = await results_to_json([gap])
    assert reported[0]["findings"]["mcp_analyzer"]["severity"] == "INFO"
    assert reason in reported[0]["findings"]["mcp_analyzer"]["threat_summary"]
    report = ReportGenerator(
        {"server_url": "https://example.com/mcp", "scan_results": reported}
    )
    for format_type in (
        OutputFormat.SUMMARY,
        OutputFormat.DETAILED,
        OutputFormat.BY_TOOL,
        OutputFormat.BY_SEVERITY,
    ):
        rendered = report.format_output(
            format_type, severity_filter=SeverityFilter.HIGH
        )
        assert reason in rendered


@pytest.mark.asyncio
async def test_llm_infrastructure_finding_is_not_a_clean_scan(config):
    from mcp.types import Tool
    from mcpscanner.core.analyzers.base import SecurityFinding

    scanner = Scanner(config)
    finding = SecurityFinding(
        severity="INFO",
        summary="LLM analysis did not complete for risky: TimeoutError during analysis",
        analyzer="LLM",
        threat_category="ANALYZER INFRASTRUCTURE",
        details={"error_type": "TimeoutError", "subject": "risky"},
    )

    async def llm_analyze(*_args, **_kwargs):
        return [finding]

    scanner._llm_analyzer = SimpleNamespace(analyze=llm_analyze)
    tool = Tool(name="risky", description="do the thing", inputSchema={"type": "object"})
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.LLM])
    assert result.status == "partial"
    assert result.is_safe is None
    assert result.findings[0] is finding
    assert any(error["analyzer"] == "LLM" for error in result.analyzer_errors)
    assert "TimeoutError during analysis" in result.analyzer_errors[-1]["message"]


@pytest.mark.asyncio
async def test_resource_read_failure_names_the_reason(config):
    scanner = Scanner(config)
    resource = SimpleNamespace(
        uri="resource://missing",
        name="missing",
        description="",
        mimeType="text/plain",
    )
    session = AsyncMock()
    session.list_resources.return_value = SimpleNamespace(resources=[resource])
    session.read_resource.side_effect = RuntimeError("disk exploded")
    patches = _patch_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        results = await scanner.scan_remote_server_resources(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
            allowed_mime_types=["text/plain"],
        )
    assert results[0].status == "failed"
    assert results[0].is_safe is None
    assert results[0].findings[0].threat_category == "ANALYZER INFRASTRUCTURE"
    assert "RuntimeError" in results[0].findings[0].summary
    assert "disk exploded" not in results[0].findings[0].summary


def _completed_tool(name: str) -> ToolScanResult:
    return ToolScanResult(
        tool_name=name,
        tool_description="d",
        status="completed",
        analyzers=[],
        findings=[],
    )


@pytest.mark.asyncio
async def test_iterator_yields_a_finished_tool_and_cancels_the_rest(config):
    from mcpscanner.core.scanner import ScanListNotice

    scanner = Scanner(config)
    tools = [
        SimpleNamespace(name="fast", description="d"),
        SimpleNamespace(name="slow", description="d"),
    ]

    async def analyze_tool(tool, analyzers, http_headers=None):
        if tool.name == "slow":
            await asyncio.Event().wait()
        return _completed_tool(tool.name)

    scanner._analyze_tool = analyze_tool
    session = AsyncMock()
    session.list_tools.return_value = SimpleNamespace(tools=tools)
    patches = _patch_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        agen = scanner.iter_remote_server_tools(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
        )
        notice = await asyncio.wait_for(agen.__anext__(), timeout=1)
        result = await asyncio.wait_for(agen.__anext__(), timeout=1)
        await asyncio.wait_for(agen.aclose(), timeout=1)
    assert isinstance(notice, ScanListNotice)
    assert notice.count == 2
    assert notice.list_complete is True
    assert result.tool_name == "fast"


@pytest.mark.asyncio
async def test_stream_heartbeats_during_a_slow_tool_and_hides_error_text(
    config, monkeypatch
):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from mcpscanner.api.router import get_scanner, router

    monkeypatch.setattr(MCPScannerConstants, "STREAM_HEARTBEAT_SECONDS", 0.05)
    scanner = Scanner(config)

    async def analyze_tool(tool, analyzers, http_headers=None):
        await asyncio.sleep(0.25)
        return _completed_tool(tool.name)

    scanner._analyze_tool = analyze_tool
    session = AsyncMock()
    session.list_tools.return_value = SimpleNamespace(
        tools=[SimpleNamespace(name="only", description="d")]
    )
    patches = _patch_session(scanner, session)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_scanner] = lambda: (lambda analyzers: scanner)
    client = TestClient(app)
    with patches[0], patches[1], patches[2]:
        with client.stream(
            "POST",
            "/scan-all-tools/stream",
            json={
                "server_url": "https://example.com/mcp",
                "analyzers": ["yara"],
            },
        ) as response:
            body = "".join(response.iter_text())
    assert response.status_code == 200
    assert "heartbeat" in body
    assert body.index('"event": "heartbeat"') < body.index('"event": "result"')
    assert '"event": "done"' in body
    assert '"complete": true' in body
    assert patches[1].new.await_count == 1

    import mcpscanner.api.router as router_mod

    def explode(*_args, **_kwargs):
        raise RuntimeError("token secret")

    monkeypatch.setattr(router_mod, "_group_findings_for_api", explode)
    with patches[0], patches[1], patches[2]:
        with client.stream(
            "POST",
            "/scan-all-tools/stream",
            json={"server_url": "https://example.com/mcp", "analyzers": ["yara"]},
        ) as response:
            error_body = "".join(response.iter_text())
            error_status = response.status_code
    assert error_status == 200
    assert '"event": "error"' in error_body
    assert "RuntimeError" in error_body
    assert "token secret" not in error_body
    assert '"event": "done"' not in error_body


@pytest.mark.asyncio
async def test_stream_disconnect_unblocks_a_full_queue(monkeypatch):
    """A full queue must not trap shutdown after the client leaves."""
    from mcpscanner.api.router import _ndjson_scan_stream

    monkeypatch.setattr(MCPScannerConstants, "STREAM_QUEUE_SIZE", 1)
    monkeypatch.setattr(MCPScannerConstants, "STREAM_HEARTBEAT_SECONDS", 30)
    second_put = asyncio.Event()
    original_put = asyncio.Queue.put

    async def track_put(self, item):
        if not second_put.is_set():
            second_put.set()
            await original_put(self, item)
            return
        await original_put(self, item)

    monkeypatch.setattr(asyncio.Queue, "put", track_put)

    async def items():
        yield SimpleNamespace(name="one")
        yield SimpleNamespace(name="two")
        await asyncio.Event().wait()

    class Request:
        async def is_disconnected(self):
            return False

    stream = _ndjson_scan_stream(
        Request(), items(), lambda result: {"name": result.name}
    )
    iterator = stream.__aiter__()
    assert "started" in await iterator.__anext__()
    await asyncio.wait_for(second_put.wait(), timeout=1)
    await asyncio.sleep(0)
    await asyncio.wait_for(iterator.aclose(), timeout=1)


@pytest.mark.asyncio
async def test_stream_done_is_incomplete_when_the_list_stops(config):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from mcpscanner.api.router import get_scanner, router

    scanner = Scanner(config)
    tool = SimpleNamespace(name="kept", description="d")

    async def analyze_tool(item, analyzers, http_headers=None):
        return _completed_tool(item.name)

    scanner._analyze_tool = analyze_tool
    scanner._list_mcp_items = AsyncMock(
        return_value=([tool], "the page limit was reached")
    )
    session = AsyncMock()
    patches = _patch_session(scanner, session)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_scanner] = lambda: (lambda analyzers: scanner)
    client = TestClient(app)
    with patches[0], patches[1], patches[2]:
        with client.stream(
            "POST",
            "/scan-all-tools/stream",
            json={
                "server_url": "https://example.com/mcp",
                "analyzers": ["yara"],
            },
        ) as response:
            body = "".join(response.iter_text())
    assert '"complete": false' in body
    assert "page limit" in body
    assert '"event": "done"' in body


def _stream_client(scanner):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from mcpscanner.api.router import get_scanner, router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_scanner] = lambda: (lambda analyzers: scanner)
    return TestClient(app)


def test_stream_setup_failures_use_scan_status_codes():
    from mcpscanner.core.exceptions import MCPConnectionError

    scanner = Scanner(Config())
    client = _stream_client(scanner)
    missing_key = client.post(
        "/scan-all-tools/stream",
        json={"server_url": "https://example.com/mcp", "analyzers": ["api"]},
    )
    assert missing_key.status_code == 404
    assert "MCP_SCANNER_API_KEY" in missing_key.json()["detail"]
    assert "event" not in missing_key.text

    empty_url = client.post(
        "/scan-all-tools/stream",
        json={"server_url": "", "analyzers": ["yara"]},
    )
    assert empty_url.status_code == 404
    assert "server URL" in empty_url.json()["detail"]

    scanner._get_mcp_session = AsyncMock(
        side_effect=MCPConnectionError("gateway refused the session")
    )
    refused = client.post(
        "/scan-all-tools/stream",
        json={"server_url": "https://example.com/mcp", "analyzers": ["yara"]},
    )
    assert refused.status_code == 502
    assert refused.json()["detail"] == "gateway refused the session"
    assert "event" not in refused.text


def test_stream_closes_the_session_when_the_body_never_starts(monkeypatch):
    from mcpscanner.api.router import _ScanStreamResponse

    scanner = Scanner(Config())
    session = AsyncMock()
    session.list_tools.return_value = SimpleNamespace(tools=[])
    patches = _patch_session(scanner, session)

    async def fail_before_the_body(self, send):
        raise OSError("client left before the body")

    monkeypatch.setattr(
        _ScanStreamResponse, "stream_response", fail_before_the_body
    )
    client = _stream_client(scanner)
    with patches[0], patches[1], patches[2]:
        with pytest.raises(Exception):
            client.post(
                "/scan-all-tools/stream",
                json={"server_url": "https://example.com/mcp", "analyzers": ["yara"]},
            )
    assert patches[1].new.await_count == 1


def test_http_stream_finishes_when_session_close_cancels_its_scope():
    """Closing the MCP client must not cancel the response task group.

    The MCP transport cancels the anyio scope it entered on the request
    task. That scope surrounds the body when the session stays open, so
    the close has to run after the chunked body is finished.
    """
    import anyio

    scanner = Scanner(Config())

    async def analyze_tool(tool, analyzers, http_headers=None):
        return _completed_tool(tool.name)

    scanner._analyze_tool = analyze_tool

    async def get_session(server_url, auth=None, **kwargs):
        scope = anyio.CancelScope()
        scope.__enter__()
        session = AsyncMock()
        session.list_tools.return_value = SimpleNamespace(
            tools=[SimpleNamespace(name="only", description="d")]
        )
        session.__aexit__ = AsyncMock()

        class Client:
            async def __aexit__(self, exc_type, exc, tb):
                scope.cancel()
                return scope.__exit__(exc_type, exc, tb)

        return Client(), session

    scanner._get_mcp_session = get_session
    scanner._server_supports_capability = lambda *_args, **_kwargs: True
    client = _stream_client(scanner)
    with client.stream(
        "POST",
        "/scan-all-tools/stream",
        json={"server_url": "https://example.com/mcp", "analyzers": ["yara"]},
    ) as response:
        body = "".join(response.iter_text())
        status = response.status_code
    assert status == 200
    assert '"event": "result"' in body
    assert '"event": "done"' in body
    assert '"complete": true' in body


@pytest.mark.asyncio
async def test_cancelled_prompt_scan_stops_inflight_fetches(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "REMOTE_SCAN_CONCURRENCY", 2)
    scanner = Scanner(config)
    prompts = [
        MCPPrompt(name="first", description="d", arguments=[]),
        MCPPrompt(name="second", description="d", arguments=[]),
    ]
    started = []
    finished = []

    async def get_prompt(name, arguments=None):
        started.append(name)
        try:
            await asyncio.Event().wait()
        finally:
            finished.append(name)

    session = AsyncMock()
    session.list_prompts.return_value = SimpleNamespace(prompts=prompts)
    session.get_prompt.side_effect = get_prompt
    patches = _patch_session(scanner, session)

    async def run():
        await scanner.scan_remote_server_prompts(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
        )

    with patches[0], patches[1], patches[2]:
        task = asyncio.create_task(run())
        for _ in range(50):
            if len(started) >= 2:
                break
            await asyncio.sleep(0.01)
        assert set(started) == {"first", "second"}
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)
    assert set(finished) == {"first", "second"}
