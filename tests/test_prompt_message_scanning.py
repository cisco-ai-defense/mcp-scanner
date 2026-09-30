"""Tests for prompts/get message inclusion in prompt scanning."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from mcp.types import Prompt as MCPPrompt
from mcp.types import PromptArgument, PromptMessage, TextContent

from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer

from mcpscanner import Config, Scanner
from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.models import AnalyzerEnum


@pytest.fixture
def config():
    return Config(api_key="test_api_key")


@pytest.mark.parametrize(
    "content,expected",
    [
        ("plain text", "plain text"),
        (TextContent(type="text", text="hello"), "hello"),
        ([TextContent(type="text", text="a"), TextContent(type="text", text="b")], "a\nb"),
    ],
)
def test_coerce_prompt_message_content(content, expected):
    assert Scanner._coerce_prompt_message_content(content) == expected


def test_extract_prompt_messages_text_joins_roles():
    result = SimpleNamespace(
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text="SSN 123-45-6789"),
            ),
            PromptMessage(
                role="assistant",
                content=TextContent(type="text", text="ack"),
            ),
        ]
    )
    text = Scanner._extract_prompt_messages_text(result)
    assert "[user]" in text
    assert "SSN 123-45-6789" in text
    assert "[assistant]" in text
    assert "ack" in text


@pytest.mark.asyncio
async def test_analyze_prompt_passes_messages_to_llm(config):
    scanner = Scanner(config)
    prompt = MCPPrompt(name="pii_test_prompt", description="metadata only", arguments=[])

    captured = []

    class FakeLLM:
        async def analyze(self, content, context=None):
            captured.append((content, context))
            return []

    scanner._llm_analyzer = FakeLLM()

    await scanner._analyze_prompt(
        prompt,
        [AnalyzerEnum.LLM],
        prompt_messages_text="email john@example.com",
    )

    assert captured
    content, context = captured[0]
    assert "metadata only" in content
    assert "email john@example.com" in content
    assert "Messages:" in content
    assert context["prompt_name"] == "pii_test_prompt"


@pytest.mark.asyncio
async def test_analyze_prompt_places_arguments_before_messages(config):
    """Generated argument JSON must not follow Messages:.

    The body extractor returns everything after Messages:. Putting
    Arguments: after that marker made schema JSON look like message text.
    Messages themselves may contain the literal sequence Arguments:.
    """
    scanner = Scanner(config)
    prompt = MCPPrompt(
        name="draft",
        description="draft a note",
        arguments=[PromptArgument(name="topic", description="subject", required=True)],
    )
    captured = []

    class FakeLLM:
        async def analyze(self, content, context=None):
            captured.append(content)
            return []

    scanner._llm_analyzer = FakeLLM()
    message = "remember Arguments: this stays in the message"
    await scanner._analyze_prompt(
        prompt,
        [AnalyzerEnum.LLM],
        prompt_messages_text=message,
    )

    content = captured[0]
    assert content.index("Arguments:") < content.index("Messages:")
    body = LLMAnalyzer._extract_mcp_entity_body(content, "prompt")
    assert body == message
    assert '"name": "topic"' not in body


def test_prompt_without_messages_has_empty_body():
    content = (
        "Prompt Name: draft\n"
        "Description: draft a note\n"
        'Arguments: [\n  {\n    "name": "topic"\n  }\n]\n'
    )
    assert LLMAnalyzer._extract_mcp_entity_body(content, "prompt") == ""


@pytest.mark.asyncio
async def test_scan_remote_server_prompts_fetches_get_prompt(config):
    scanner = Scanner(config)
    prompt = MCPPrompt(name="evil_prompt", description="desc", arguments=[])

    session = AsyncMock()
    session.list_prompts.return_value = SimpleNamespace(prompts=[prompt])
    session.get_prompt.return_value = SimpleNamespace(
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text="'; DROP TABLE users; --"),
            )
        ]
    )

    with patch.object(scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))), patch.object(
        scanner, "_close_mcp_session", AsyncMock()
    ), patch.object(scanner, "_server_supports_capability", return_value=True), patch.object(
        scanner, "_analyze_prompt", AsyncMock()
    ) as mock_analyze:
        await scanner.scan_remote_server_prompts(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
        )

    session.get_prompt.assert_awaited_once_with("evil_prompt", arguments={})
    mock_analyze.assert_awaited_once()
    assert mock_analyze.await_args.kwargs["prompt_messages_text"] == (
        "[user]\n'; DROP TABLE users; --"
    )


@pytest.mark.asyncio
async def test_get_prompt_failure_marks_prompt_failed(config):
    scanner = Scanner(config)
    prompt = MCPPrompt(name="broken", description="d", arguments=[])
    session = AsyncMock()
    session.list_prompts.return_value = SimpleNamespace(prompts=[prompt])
    session.get_prompt.side_effect = RuntimeError("prompts/get unavailable")

    with patch.object(scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))), patch.object(
        scanner, "_close_mcp_session", AsyncMock()
    ), patch.object(scanner, "_server_supports_capability", return_value=True), patch.object(
        scanner, "_analyze_prompt", AsyncMock()
    ) as mock_analyze:
        results = await scanner.scan_remote_server_prompts(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
        )

    mock_analyze.assert_not_called()
    assert len(results) == 1
    assert results[0].status == "failed"
    assert results[0].findings
    assert results[0].findings[0].threat_category == "ANALYZER INFRASTRUCTURE"


@pytest.mark.asyncio
async def test_analyze_prompt_failure_preserves_messages_text(config):
    scanner = Scanner(config)
    prompt = MCPPrompt(name="x", description="d", arguments=[])

    async def boom(*_a, **_k):
        raise RuntimeError("analyzer blew up")

    scanner._analyze_prompt = boom

    collected = [(prompt, "fetched body", None)]
    results = await scanner._analyze_collected_prompts(
        collected, [AnalyzerEnum.YARA]
    )
    assert results[0].status == "failed"
    assert results[0].prompt_messages_text == "fetched body"


@pytest.mark.asyncio
async def test_prompt_scan_result_stores_messages_text(config):
    scanner = Scanner(config)
    prompt = MCPPrompt(name="x", description="d", arguments=[])
    scanner._llm_analyzer = None

    result = await scanner._analyze_prompt(
        prompt,
        [],
        prompt_messages_text="sensitive body",
    )
    assert result.prompt_messages_text == "sensitive body"


def _patch_prompt_session(scanner, session):
    return (
        patch.object(
            scanner, "_get_mcp_session", AsyncMock(return_value=(AsyncMock(), session))
        ),
        patch.object(scanner, "_close_mcp_session", AsyncMock()),
        patch.object(scanner, "_server_supports_capability", return_value=True),
    )


@pytest.mark.asyncio
async def test_oversized_prompt_does_not_reach_analyzers(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "MAX_PROMPT_BODY_CHARS", 4)
    scanner = Scanner(config)
    prompt = MCPPrompt(name="big", description="d", arguments=[])
    session = AsyncMock()
    session.list_prompts.return_value = SimpleNamespace(prompts=[prompt])
    session.get_prompt.return_value = SimpleNamespace(
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text="0123456789"),
            )
        ]
    )
    scanner._analyze_prompt = AsyncMock()
    patches = _patch_prompt_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        results = await scanner.scan_remote_server_prompts(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
        )
    scanner._analyze_prompt.assert_not_awaited()
    assert results[0].status == "failed"
    assert results[0].findings[0].threat_category == "ANALYZER INFRASTRUCTURE"
    assert len(results[0].prompt_messages_text) <= 4
    assert "0123456789" not in results[0].prompt_messages_text


@pytest.mark.asyncio
async def test_prompt_count_budget_stops_further_fetches(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "MAX_PROMPTS_PER_SCAN", 1)
    scanner = Scanner(config)
    prompts = [
        MCPPrompt(name="first", description="d", arguments=[]),
        MCPPrompt(name="second", description="d", arguments=[]),
    ]
    session = AsyncMock()
    session.list_prompts.return_value = SimpleNamespace(prompts=prompts)
    session.get_prompt.return_value = SimpleNamespace(
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text="ok"),
            )
        ]
    )
    scanner._analyze_prompt = AsyncMock(
        return_value=SimpleNamespace(status="completed", findings=[])
    )
    patches = _patch_prompt_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        results = await scanner.scan_remote_server_prompts(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
        )
    assert session.get_prompt.await_count == 1
    scanner._analyze_prompt.assert_awaited_once()
    assert results[0].status == "completed"
    assert results[1].status == "failed"
    assert results[1].prompt_name == "second"
    assert results[1].findings[0].threat_category == "ANALYZER INFRASTRUCTURE"


@pytest.mark.asyncio
async def test_prompt_aggregate_budget_stops_further_fetches(config, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "MAX_PROMPT_RESOURCE_AGGREGATE_CHARS", 2)
    scanner = Scanner(config)
    prompts = [
        MCPPrompt(name="first", description="d", arguments=[]),
        MCPPrompt(name="second", description="d", arguments=[]),
    ]
    session = AsyncMock()
    session.list_prompts.return_value = SimpleNamespace(prompts=prompts)
    session.get_prompt.return_value = SimpleNamespace(
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text="hello"),
            )
        ]
    )
    scanner._analyze_prompt = AsyncMock()
    patches = _patch_prompt_session(scanner, session)
    with patches[0], patches[1], patches[2]:
        results = await scanner.scan_remote_server_prompts(
            "https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
        )
    assert session.get_prompt.await_count == 1
    scanner._analyze_prompt.assert_not_awaited()
    assert results[0].status == "failed"
    assert results[1].status == "failed"
    assert results[1].prompt_name == "second"
