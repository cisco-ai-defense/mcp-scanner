# Development Guide

## Testing

The SDK includes a comprehensive test suite. To run the tests:

```bash
uv run pytest
```

### MCP protocol integration tests

After changes to live scanning or the bundled `mcp` dependency, run the modern-protocol integration tests:

```bash
uv run pytest tests/test_stdio_modern_integration.py tests/test_scanner.py -k "negotiate or stdio_modern"
```

These verify `server/discover` negotiation at `2026-07-28` and fallback to legacy `initialize()` for older servers.

For more detailed coverage information:

```bash
uv run pytest --cov=mcpscanner --cov-report=term
```

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. For detailed contributing guidelines, please see [CONTRIBUTING.md](CONTRIBUTING.md)
