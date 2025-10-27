"""
Lightweight tracing utility emitting JSON spans to stdout.

Usage:
- Toggle via env MCP_SCANNER_TRACING=1 or set_tracing_enabled(True)
- Use get_tracer().span(name, attrs) as sync/async context manager
"""

import contextvars
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, Optional


_trace_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "trace_id", default=None
)
_span_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "span_id", default=None
)
_enabled: bool = str(os.getenv("MCP_SCANNER_TRACING", "")).lower() in (
    "1",
    "true",
    "yes",
)


def _now_iso() -> str:
    # Millisecond resolution timestamp in ISO 8601
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1)*1000):03d}Z"


def is_tracing_enabled() -> bool:
    return _enabled


def set_tracing_enabled(enabled: bool) -> None:
    global _enabled
    _enabled = bool(enabled)


def get_tracer() -> "Tracer":
    return Tracer(_enabled)


class NullSpan:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class Span:
    def __init__(self, name: str, attrs: Optional[Dict[str, Any]] = None):
        self.name = name
        self.attrs = attrs or {}
        self._start_ns: Optional[int] = None
        self._status: str = "ok"
        self._err: Optional[str] = None
        self._trace_id: Optional[str] = None
        self._span_id: Optional[str] = None
        self._parent_id: Optional[str] = None
        self._parent_token = None
        self._trace_token = None

    def _begin(self):
        self._trace_id = _trace_id_var.get()
        if not self._trace_id:
            self._trace_id = uuid.uuid4().hex
            self._trace_token = _trace_id_var.set(self._trace_id)
        self._parent_id = _span_id_var.get()
        self._span_id = uuid.uuid4().hex
        self._parent_token = _span_id_var.set(self._span_id)
        self._start_ns = time.perf_counter_ns()

    def _finish(self, exc_type=None, exc=None):
        # Restore context
        if self._parent_token is not None:
            _span_id_var.reset(self._parent_token)
        if self._trace_token is not None:
            _trace_id_var.reset(self._trace_token)

        dur_ms = None
        if self._start_ns is not None:
            dur_ms = (time.perf_counter_ns() - self._start_ns) / 1_000_000.0

        if exc_type is not None and exc is not None:
            self._status = "error"
            self._err = str(exc)

        # Redact sensitive keys in attrs
        redacted = {}
        for k, v in self.attrs.items():
            if k.lower() in ("api_key", "bearer_token", "authorization", "secret"):
                redacted[k] = "***"
            else:
                redacted[k] = v

        record = {
            "ts": _now_iso(),
            "dur_ms": dur_ms,
            "name": self.name,
            "trace_id": self._trace_id,
            "span_id": self._span_id,
            "parent_id": self._parent_id,
            "attrs": redacted,
            "status": self._status,
        }
        if self._err:
            record["err"] = self._err

        try:
            sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
            sys.stdout.flush()
        except Exception:
            # Never raise from tracing
            pass

    async def __aenter__(self):
        self._begin()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self._finish(exc_type, exc)
        return False

    def __enter__(self):
        self._begin()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._finish(exc_type, exc)
        return False


class Tracer:
    def __init__(self, enabled: bool = False):
        self._enabled = bool(enabled)

    def span(self, name: str, attrs: Optional[Dict[str, Any]] = None):
        if not self._enabled:
            return NullSpan()
        return Span(name, attrs or {})


