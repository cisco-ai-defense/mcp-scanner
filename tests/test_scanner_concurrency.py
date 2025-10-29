import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.result import ToolScanResult, PromptScanResult, ResourceScanResult


class DummyTool:
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description


class DummyPrompt:
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description


class DummyResource:
    def __init__(self, uri: str, name: str = "", description: str = "", mime: str = "text/plain"):
        self.uri = uri
        self.name = name
        self.description = description
        self.mimeType = mime


class DummyResourceContents:
    def __init__(self, text: str):
        # Emulate the MCP content shape with .text
        self.contents = [SimpleNamespace(text=text)]


@pytest.mark.asyncio
async def test_tools_concurrency_bounded(monkeypatch):
    """Ensure tool analyses never exceed configured concurrency bound."""
    cfg = Config(max_concurrency_tools=2)
    scanner = Scanner(cfg)

    # Create many dummy tools
    tools = [DummyTool(name=f"tool_{i}") for i in range(10)]

    # Fake session with list_tools
    class ToolList:
        def __init__(self, tools):
            self.tools = tools

    class DummySession:
        async def list_tools(self):
            await asyncio.sleep(0)  # yield control
            return ToolList(tools)

    async def fake_get_session(self, server_url, auth=None):
        return None, DummySession()

    async def fake_close(self, client_context, session):
        return None

    # Track in-flight concurrency for _analyze_tool
    current = 0
    peak = 0

    async def fake_analyze_tool(self, tool, analyzers, http_headers):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.02)
        current -= 1
        return ToolScanResult(
            tool_name=tool.name,
            tool_description=getattr(tool, "description", ""),
            status="completed",
            analyzers=[a.value for a in analyzers] if analyzers else [],
            findings=[],
        )

    monkeypatch.setattr(Scanner, "_get_mcp_session", fake_get_session)
    monkeypatch.setattr(Scanner, "_close_mcp_session", fake_close)
    monkeypatch.setattr(Scanner, "_analyze_tool", fake_analyze_tool)

    _ = await scanner.scan_remote_server_tools("http://example.com", analyzers=[AnalyzerEnum.YARA])

    assert peak <= 2, f"Observed peak concurrency {peak} exceeds bound"


@pytest.mark.asyncio
async def test_prompts_concurrency_bounded(monkeypatch):
    cfg = Config(max_concurrency_prompts=2)
    scanner = Scanner(cfg)

    prompts = [DummyPrompt(name=f"prompt_{i}", description="desc") for i in range(10)]

    class PromptList:
        def __init__(self, prompts):
            self.prompts = prompts

    class DummySession:
        async def list_prompts(self):
            await asyncio.sleep(0)
            return PromptList(prompts)

    async def fake_get_session(self, server_url, auth=None):
        return None, DummySession()

    async def fake_close(self, client_context, session):
        return None

    current = 0
    peak = 0

    async def fake_analyze_prompt(self, prompt, analyzers, http_headers):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.02)
        current -= 1
        return PromptScanResult(
            prompt_name=prompt.name,
            prompt_description=prompt.description,
            status="completed",
            analyzers=[a.value for a in analyzers] if analyzers else [],
            findings=[],
        )

    monkeypatch.setattr(Scanner, "_get_mcp_session", fake_get_session)
    monkeypatch.setattr(Scanner, "_close_mcp_session", fake_close)
    monkeypatch.setattr(Scanner, "_analyze_prompt", fake_analyze_prompt)

    _ = await scanner.scan_remote_server_prompts("http://example.com", analyzers=[AnalyzerEnum.YARA])

    assert peak <= 2, f"Observed peak concurrency {peak} exceeds bound"


@pytest.mark.asyncio
async def test_resources_concurrency_bounded_read_and_analyze(monkeypatch):
    cfg = Config(max_concurrency_resources=2)
    scanner = Scanner(cfg)

    resources = [
        DummyResource(uri=f"file://resource_{i}.txt", name=f"res_{i}") for i in range(10)
    ]

    class ResourceList:
        def __init__(self, resources):
            self.resources = resources

    class DummySession:
        async def list_resources(self):
            await asyncio.sleep(0)
            return ResourceList(resources)

        async def read_resource(self, uri):
            # Simulate some IO
            await asyncio.sleep(0.01)
            return DummyResourceContents(text=f"content for {uri}")

    async def fake_get_session(self, server_url, auth=None):
        return None, DummySession()

    async def fake_close(self, client_context, session):
        return None

    current = 0
    peak = 0

    async def fake_analyze_resource(
        self,
        resource_content: str,
        resource_uri: str,
        resource_name: str,
        resource_description: str,
        resource_mime_type: str,
        analyzers,
        http_headers=None,
    ):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.02)
        current -= 1
        return ResourceScanResult(
            resource_uri=resource_uri,
            resource_name=resource_name,
            resource_mime_type=resource_mime_type,
            status="completed",
            analyzers=[a.value for a in analyzers] if analyzers else [],
            findings=[],
        )

    monkeypatch.setattr(Scanner, "_get_mcp_session", fake_get_session)
    monkeypatch.setattr(Scanner, "_close_mcp_session", fake_close)
    monkeypatch.setattr(Scanner, "_analyze_resource", fake_analyze_resource)

    _ = await scanner.scan_remote_server_resources(
        "http://example.com", analyzers=[AnalyzerEnum.YARA]
    )

    assert peak <= 2, f"Observed peak concurrency {peak} exceeds bound"


