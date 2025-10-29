import asyncio
from types import SimpleNamespace

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.api_analyzer import ApiAnalyzer


class DummyResponse:
    def __init__(self, status_code=200, json_payload=None):
        self.status_code = status_code
        self._json = json_payload or {"is_safe": True, "classifications": []}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


class CountingClient:
    instances = 0

    def __init__(self, *args, **kwargs):
        CountingClient.instances += 1

    async def post(self, *args, **kwargs):
        return DummyResponse()


@pytest.mark.asyncio
async def test_single_asyncclient_created_per_analyzer(monkeypatch):
    # Swap httpx.AsyncClient with our counting stub
    monkeypatch.setattr(
        "mcpscanner.core.analyzers.api_analyzer.httpx.AsyncClient", CountingClient
    )

    analyzer = ApiAnalyzer(Config(api_key="dummy"))

    # Call analyze twice; client should be constructed once (on init)
    findings1 = await analyzer.analyze("safe content")
    findings2 = await analyzer.analyze("still safe")

    assert CountingClient.instances == 1
    assert findings1 == [] and findings2 == []
