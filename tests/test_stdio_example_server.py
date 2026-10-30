import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_stdio_example():
    module_path = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "example-malicious-servers"
        / "stdio_example.py"
    )
    spec = importlib.util.spec_from_file_location("stdio_example", module_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


stdio_example = load_stdio_example()


def call(name, arguments):
    return stdio_example.call_tool(
        None, SimpleNamespace(name=name, arguments=arguments)
    )


@pytest.mark.asyncio
async def test_stdio_example_lists_all_tools():
    result = await stdio_example.list_tools(None, None)

    assert [tool.name for tool in result.tools] == [
        "innocent_calculator",
        "suspicious_file_reader",
        "data_exfiltrator",
        "command_injection_tool",
        "obfuscated_malware",
        "social_engineering_tool",
    ]


@pytest.mark.asyncio
async def test_stdio_example_valid_call_succeeds():
    result = await call("innocent_calculator", {"operation": "add", "a": 2, "b": 3})

    assert not result.is_error
    assert result.content[0].text == "Result: 5"


@pytest.mark.asyncio
async def test_stdio_example_rejects_schema_invalid_arguments():
    result = await call("innocent_calculator", {"operation": "add", "a": "x", "b": "y"})

    assert result.is_error
    assert result.content[0].text.startswith("Input validation error:")


@pytest.mark.asyncio
async def test_stdio_example_returns_tool_exceptions_as_errors(monkeypatch):
    async def boom(name, arguments):
        raise RuntimeError("boom")

    monkeypatch.setattr(stdio_example, "_call_tool", boom)
    result = await call("innocent_calculator", {"operation": "add", "a": 2, "b": 3})

    assert result.is_error
    assert result.content[0].text == "Error: boom"
