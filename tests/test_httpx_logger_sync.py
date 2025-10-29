import asyncio
import logging

import pytest

from mcpscanner import Config, Scanner


class DummyCtx:
    async def __aenter__(self):
        await asyncio.sleep(0.005)
        # Return tuple like (read, write, ...)
        return (object(), object(), object())

    async def __aexit__(self, exc_type, exc, tb):
        return False


class DummySession:
    def __init__(self, read, write):
        self._read = read
        self._write = write

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def initialize(self):
        await asyncio.sleep(0.002)


@pytest.mark.asyncio
async def test_httpx_logger_restored_after_concurrent_sessions(monkeypatch):
    """Concurrent _get_mcp_session calls must not leak handlers or logger level/propagate changes."""
    # Patch client constructors used by _get_mcp_session
    monkeypatch.setattr("mcpscanner.core.scanner.sse_client", lambda *args, **kwargs: DummyCtx())
    monkeypatch.setattr("mcpscanner.core.scanner.streamablehttp_client", lambda *args, **kwargs: DummyCtx())

    def client_session_ctor(read, write):
        return DummySession(read, write)

    monkeypatch.setattr("mcpscanner.core.scanner.ClientSession", client_session_ctor)

    # Capture original logger state
    httpx_logger = logging.getLogger("httpx")
    orig_level = httpx_logger.level
    orig_propagate = httpx_logger.propagate
    orig_handlers = list(httpx_logger.handlers)

    scanner = Scanner(Config())

    async def one_call():
        client_ctx, sess = await scanner._get_mcp_session("http://localhost:12345")
        # Immediately close to avoid dangling
        await scanner._close_mcp_session(client_ctx, sess)

    # Run multiple in parallel
    await asyncio.gather(*[one_call() for _ in range(10)])

    # Assert logger state restored
    assert httpx_logger.level == orig_level
    assert httpx_logger.propagate == orig_propagate
    assert len(httpx_logger.handlers) == len(orig_handlers)
