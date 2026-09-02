# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""HTTP tests for POST /scan-behavioral-source."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcpscanner.api.router import get_scanner, router
from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.models import AnalyzerEnum


@pytest.fixture
def api_root(tmp_path):
    """Writable directory used as the confined API root."""
    sample = tmp_path / "server.py"
    sample.write_text("def handler():\n    pass\n", encoding="utf-8")
    subdir = tmp_path / "pkg"
    subdir.mkdir()
    (subdir / "tool.py").write_text("def run():\n    pass\n", encoding="utf-8")
    return tmp_path


def _app_with_factory(factory, *, api_root: str, enabled: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_scanner] = lambda: factory
    return app


@pytest.fixture
def behavioral_app(api_root, monkeypatch):
    """FastAPI app with behavioral source API enabled and a mock scanner."""
    monkeypatch.setattr(MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ENABLED", True)
    monkeypatch.setattr(
        MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ROOT", str(api_root)
    )

    finding = SecurityFinding(
        analyzer="Behavioral",
        severity="SAFE",
        summary="ok",
        threat_category="",
        details={"function_name": "handler"},
    )
    behavioral = MagicMock()
    behavioral.analyze = AsyncMock(return_value=[finding])
    behavioral.analyzed_functions = 1

    scanner = MagicMock()
    scanner._behavioral_analyzer = behavioral

    def factory(analyzers):
        assert analyzers == [AnalyzerEnum.BEHAVIORAL]
        return scanner

    app = _app_with_factory(factory, api_root=str(api_root))
    return app, behavioral, api_root


class TestBehavioralSourceEndpoint:
    def test_disabled_returns_403_without_scanner_override(self, api_root, monkeypatch):
        monkeypatch.setattr(
            MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ENABLED", False
        )
        monkeypatch.setattr(
            MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ROOT", str(api_root)
        )
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post(
            "/scan-behavioral-source", json={"source_path": "server.py"}
        )
        assert resp.status_code == 403
        assert "disabled" in resp.json()["detail"].lower()

    def test_missing_root_returns_503_without_scanner_override(self, monkeypatch):
        monkeypatch.setattr(
            MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ENABLED", True
        )
        monkeypatch.setattr(MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ROOT", "")
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post(
            "/scan-behavioral-source", json={"source_path": "server.py"}
        )
        assert resp.status_code == 503
        assert "root" in resp.json()["detail"].lower()

    def test_enabled_without_scanner_factory_returns_503(self, api_root, monkeypatch):
        monkeypatch.setattr(
            MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ENABLED", True
        )
        monkeypatch.setattr(
            MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ROOT", str(api_root)
        )
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post(
            "/scan-behavioral-source", json={"source_path": "server.py"}
        )
        assert resp.status_code == 503
        assert "dependency_overrides" in resp.json()["detail"]

    def test_traversal_rejected_with_400(self, behavioral_app):
        app, _, _ = behavioral_app
        client = TestClient(app)
        resp = client.post(
            "/scan-behavioral-source", json={"source_path": "../etc/passwd"}
        )
        assert resp.status_code in (400, 422)

    def test_absolute_path_rejected(self, behavioral_app):
        app, _, _ = behavioral_app
        client = TestClient(app)
        resp = client.post(
            "/scan-behavioral-source", json={"source_path": "/etc/passwd"}
        )
        assert resp.status_code == 422

    def test_missing_path_returns_404(self, behavioral_app):
        app, _, _ = behavioral_app
        client = TestClient(app)
        resp = client.post(
            "/scan-behavioral-source", json={"source_path": "missing.py"}
        )
        assert resp.status_code == 404

    def test_missing_behavioral_analyzer_returns_400(self, api_root, monkeypatch):
        monkeypatch.setattr(
            MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ENABLED", True
        )
        monkeypatch.setattr(
            MCPScannerConstants, "BEHAVIORAL_SOURCE_API_ROOT", str(api_root)
        )
        scanner = MagicMock()
        scanner._behavioral_analyzer = None

        def factory(_analyzers):
            return scanner

        app = _app_with_factory(factory, api_root=str(api_root))
        client = TestClient(app)
        resp = client.post(
            "/scan-behavioral-source", json={"source_path": "server.py"}
        )
        assert resp.status_code == 400
        assert "llm" in resp.json()["detail"].lower()

    def test_directory_scan_returns_findings(self, behavioral_app):
        app, behavioral, api_root = behavioral_app
        client = TestClient(app)
        resp = client.post("/scan-behavioral-source", json={"source_path": "pkg"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["finding_count"] == 1
        assert str(api_root / "pkg") in body["source_path"]
        behavioral.analyze.assert_awaited_once()

    def test_happy_path_returns_findings(self, behavioral_app):
        app, behavioral, api_root = behavioral_app
        client = TestClient(app)
        resp = client.post(
            "/scan-behavioral-source", json={"source_path": "server.py"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["finding_count"] == 1
        assert body["analyzed_functions"] == 1
        assert body["findings"][0]["severity"] == "SAFE"
        assert str(api_root / "server.py") in body["source_path"]
        behavioral.analyze.assert_awaited_once()
