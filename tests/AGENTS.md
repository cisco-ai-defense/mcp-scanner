# tests/AGENTS.md

This file provides detailed context for AI coding agents working on the **test suite** in the `tests/` directory.

**📁 Parent Guide:** [`../AGENTS.md`](../AGENTS.md) - Global project overview and rules

---

## Overview

The `tests/` directory contains a comprehensive test suite with 40+ test files covering all aspects of the MCP Scanner. The test suite uses pytest and includes unit tests, integration tests, and mock fixtures for external APIs.

## Test Structure

```
tests/
├── test_behavioral_analyzer.py      # Behavioral analysis tests
├── test_scanner.py                  # Scanner orchestration tests
├── test_instructions_scanning.py    # Instructions scanning tests
├── test_llm_analyzer.py             # LLM analyzer tests
├── test_yara_analyzer.py            # YARA analyzer tests
├── test_api_analyzer.py             # API analyzer tests
├── test_auth.py                     # Authentication tests
├── test_result.py                   # Result data structure tests
├── test_report_generator.py         # Output formatting tests
├── test_cli.py                      # CLI tests
└── ... (30+ more test files)
```

## Testing Guidelines

### General Principles

1. **Test Coverage**: Aim for 80%+ coverage on core components
2. **Mock External APIs**: Always mock LLM and Cisco AI Defense API calls
3. **Test Both Success and Failure**: Test happy paths and error cases
4. **Use Fixtures**: Leverage pytest fixtures for common setup
5. **Deterministic Tests**: Tests should be reproducible and not flaky

### Writing New Tests

#### 1. Test File Naming
- Name test files `test_<module_name>.py`
- Place in `tests/` directory at root level
- Mirror the structure of the code being tested

#### 2. Test Function Naming
- Use descriptive names: `test_<function>_<scenario>_<expected_result>`
- Examples:
  - `test_behavioral_analyzer_detects_mismatch_returns_finding()`
  - `test_scanner_handles_missing_api_key_raises_error()`
  - `test_yara_analyzer_empty_content_returns_empty_list()`

#### 3. Test Structure (AAA Pattern)
```python
def test_something():
    # Arrange: Set up test data and mocks
    mock_data = {"key": "value"}
    
    # Act: Execute the code being tested
    result = function_under_test(mock_data)
    
    # Assert: Verify the expected outcome
    assert result == expected_value
```

### Mocking External APIs

#### LLM API Mocking

Always mock LLM calls to avoid costs and ensure deterministic tests:

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_behavioral_analyzer_with_mock_llm():
    # Mock the LLM response
    mock_response = {
        "is_aligned": False,
        "severity": "HIGH",
        "threat_categories": ["CODE_EXECUTION"],
        "explanation": "Test finding"
    }
    
    with patch('mcpscanner.core.analyzers.llm_analyzer.LLMAnalyzer.analyze') as mock_llm:
        mock_llm.return_value = [SecurityFinding(...)]
        
        # Run test
        analyzer = BehavioralCodeAnalyzer()
        results = await analyzer.analyze(code, context)
        
        # Verify
        assert len(results) > 0
        mock_llm.assert_called_once()
```

#### Cisco AI Defense API Mocking

Mock API calls to avoid network dependencies:

```python
@pytest.mark.asyncio
async def test_api_analyzer_with_mock():
    mock_response = {
        "is_safe": False,
        "classifications": [
            {"name": "prompt_injection", "score": 0.95}
        ]
    }
    
    with patch('httpx.AsyncClient.post') as mock_post:
        mock_post.return_value.json.return_value = mock_response
        
        analyzer = APIAnalyzer(api_key="test-key")
        results = await analyzer.analyze(content, context)
        
        assert len(results) > 0
```

### Pytest Fixtures

#### Common Fixtures

Create reusable fixtures in `conftest.py`:

```python
import pytest

@pytest.fixture
def sample_mcp_tool():
    """Sample MCP tool for testing"""
    return {
        "name": "test_tool",
        "description": "A test tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "param": {"type": "string"}
            }
        }
    }

@pytest.fixture
def mock_scanner_config():
    """Mock scanner configuration"""
    return {
        "llm_api_key": "test-key",
        "llm_model": "gpt-4o",
        "analyzers": ["behavioral", "llm"]
    }

@pytest.fixture
async def mock_llm_analyzer():
    """Mock LLM analyzer that returns no findings"""
    analyzer = AsyncMock()
    analyzer.analyze.return_value = []
    return analyzer
```

### Testing Async Code

Use `pytest.mark.asyncio` for async tests:

```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result is not None
```

### Testing Error Handling

Always test error cases:

```python
def test_analyzer_handles_invalid_input():
    analyzer = SomeAnalyzer()
    
    with pytest.raises(ValueError, match="Invalid input"):
        analyzer.analyze(None, {})

@pytest.mark.asyncio
async def test_scanner_handles_api_timeout():
    with patch('httpx.AsyncClient.post', side_effect=httpx.TimeoutException):
        scanner = Scanner()
        
        with pytest.raises(ScannerError):
            await scanner.scan_remote_server("http://example.com")
```

### Testing CLI

Test CLI commands using pytest's `capsys` or `click.testing.CliRunner`:

```python
from click.testing import CliRunner
from mcpscanner.cli import cli

def test_cli_behavioral_command():
    runner = CliRunner()
    result = runner.invoke(cli, ['behavioral', '/path/to/code'])
    
    assert result.exit_code == 0
    assert "Scan complete" in result.output

def test_cli_invalid_analyzer():
    runner = CliRunner()
    result = runner.invoke(cli, ['--analyzers', 'invalid', 'behavioral', '/path'])
    
    assert result.exit_code != 0
    assert "Invalid analyzer" in result.output
```

## Test Coverage Requirements

### Core Components (80%+ coverage required)

- **Analyzers**: `behavioral/`, `api_analyzer.py`, `llm_analyzer.py`, `yara_analyzer.py`
- **Scanner**: `scanner.py`
- **Results**: `result.py`, `models.py`
- **Report Generator**: `report_generator.py`

### CLI (Test all subcommands)

- Test each subcommand: `remote`, `prompts`, `resources`, `instructions`, `behavioral`, `stdio`, `config`, `known-configs`
- Test global flags: `--analyzers`, `--output`, `--format`, `--detailed`, `--verbose`
- Test flag combinations
- Test error cases (missing args, invalid values)

### Integration Tests

Test end-to-end workflows:

```python
@pytest.mark.asyncio
async def test_full_scan_workflow():
    """Test complete scan from input to output"""
    scanner = Scanner(config)
    
    # Mock external dependencies
    with patch('mcpscanner.core.analyzers.llm_analyzer.LLMAnalyzer.analyze') as mock_llm:
        mock_llm.return_value = []
        
        # Run full scan
        results = await scanner.scan_local_code("/path/to/code")
        
        # Verify results
        assert results is not None
        assert isinstance(results, list)
```

## Running Tests

### Run All Tests
```bash
uv run pytest
```

### Run Specific Test File
```bash
uv run pytest tests/test_behavioral_analyzer.py
```

### Run Specific Test Function
```bash
uv run pytest tests/test_behavioral_analyzer.py::test_function_name
```

### Run with Coverage
```bash
uv run pytest --cov=mcpscanner --cov-report=html
```

### Run with Verbose Output
```bash
uv run pytest -v
```

### Run Tests Matching Pattern
```bash
uv run pytest -k "behavioral"
```

## Common Testing Patterns

### Pattern 1: Testing Analyzer Output

```python
@pytest.mark.asyncio
async def test_analyzer_returns_security_finding():
    analyzer = SomeAnalyzer()
    results = await analyzer.analyze(malicious_content, {})
    
    assert len(results) > 0
    assert isinstance(results[0], SecurityFinding)
    assert results[0].severity in ["HIGH", "MEDIUM", "LOW"]
    assert results[0].threat_category is not None
```

### Pattern 2: Testing with Multiple Scenarios

```python
@pytest.mark.parametrize("content,expected_severity", [
    ("eval(user_input)", "HIGH"),
    ("os.system(user_input)", "HIGH"),
    ("print(user_input)", "SAFE"),
])
@pytest.mark.asyncio
async def test_analyzer_severity_levels(content, expected_severity):
    analyzer = LLMAnalyzer()
    results = await analyzer.analyze(content, {})
    
    if expected_severity == "SAFE":
        assert len(results) == 0
    else:
        assert results[0].severity == expected_severity
```

### Pattern 3: Testing Configuration

```python
def test_scanner_loads_config_from_env(monkeypatch):
    monkeypatch.setenv("MCP_SCANNER_LLM_API_KEY", "test-key")
    monkeypatch.setenv("MCP_SCANNER_LLM_MODEL", "gpt-4o")
    
    scanner = Scanner()
    
    assert scanner.config.llm_api_key == "test-key"
    assert scanner.config.llm_model == "gpt-4o"
```

### Pattern 4: Testing File Operations

```python
def test_scanner_reads_local_files(tmp_path):
    # Create temporary test file
    test_file = tmp_path / "test.py"
    test_file.write_text("def test(): pass")
    
    scanner = Scanner()
    results = scanner.scan_local_code(str(tmp_path))
    
    assert results is not None
```

## Debugging Tests

### Print Debug Information
```python
def test_something():
    result = function_under_test()
    print(f"Debug: result = {result}")  # Will show with pytest -s
    assert result is not None
```

### Use pytest's Built-in Debugging
```bash
# Drop into debugger on failure
uv run pytest --pdb

# Drop into debugger at start of test
uv run pytest --trace
```

### Check Test Output
```bash
# Show print statements
uv run pytest -s

# Show more verbose output
uv run pytest -vv
```

## Common Issues

### Issue 1: Async Tests Not Running
**Problem**: Async tests fail with "coroutine was never awaited"
**Solution**: Add `@pytest.mark.asyncio` decorator

### Issue 2: Mocks Not Working
**Problem**: Mock is not being called
**Solution**: Ensure you're patching the correct import path (where it's used, not where it's defined)

### Issue 3: Flaky Tests
**Problem**: Tests pass sometimes, fail other times
**Solution**: 
- Ensure tests are isolated (no shared state)
- Mock all external dependencies
- Use deterministic test data

### Issue 4: Slow Tests
**Problem**: Test suite takes too long
**Solution**:
- Mock all network calls
- Mock all LLM calls
- Use smaller test datasets
- Run tests in parallel: `pytest -n auto`

## Best Practices

1. **Isolate Tests**: Each test should be independent
2. **Mock External Dependencies**: Never make real API calls in tests
3. **Use Descriptive Names**: Test names should explain what they test
4. **Test Edge Cases**: Don't just test the happy path
5. **Keep Tests Fast**: Aim for <1s per test
6. **Use Fixtures**: Reuse common setup code
7. **Test Error Messages**: Verify error messages are helpful
8. **Document Complex Tests**: Add comments explaining non-obvious test logic

## Contributing Tests

When adding new features:

1. Write tests BEFORE implementing the feature (TDD)
2. Ensure all tests pass before submitting PR
3. Add tests for both success and failure cases
4. Update this guide if you introduce new testing patterns
5. Aim for 80%+ coverage on new code

---

**Last Updated**: December 2025
**Maintained By**: Cisco AI Defense Team
