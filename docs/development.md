# Development Guide

## Testing

The SDK includes a comprehensive test suite. To run the tests:

```bash
uv run pytest
```

For more detailed coverage information:

```bash
uv run pytest --cov=mcpscanner --cov-report=term
```

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. For detailed contributing guidelines, please see [CONTRIBUTING.md](CONTRIBUTING.md)

## Tracing and Profiling (Lightweight JSON spans)

Enable lightweight tracing to measure latencies across scanner, analyzers, API routes, and report formatting. Traces are emitted as one JSON line per span to stdout. Disabled by default.

- Toggle via environment: `MCP_SCANNER_TRACING=1`
- CLI flag: `--trace`
- Output fields per span: `ts`, `dur_ms`, `name`, `trace_id`, `span_id`, `parent_id`, `attrs`, `status`, `err`

Example span line:

```json
{"ts":"2025-10-25T17:32:10.123Z","dur_ms":42.7,"name":"scanner.analyze.tools","trace_id":"...","span_id":"...","parent_id":"...","attrs":{"count":3},"status":"ok"}
```

Notes:
- Minimal overhead when disabled (no-op fast path)
- Secrets are redacted in attributes
- Large payloads are avoided; attributes only include sizes/counts and identifiers
