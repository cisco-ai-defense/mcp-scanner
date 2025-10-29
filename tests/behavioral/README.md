# Behavioral Code Analyzer Tests

This directory contains tests for the Behavioral Code Analyzer components.

## Test Structure

The tests are organized by component:

### Core Components
- **`test_code_analyzer.py`** - Main BehavioralCodeAnalyzer orchestrator tests
- **`test_alignment_orchestrator.py`** - Alignment checking workflow tests

### Alignment Components
- **`test_prompt_builder.py`** - AlignmentPromptBuilder tests
- **`test_llm_client.py`** - AlignmentLLMClient tests
- **`test_response_validator.py`** - AlignmentResponseValidator tests

### Analysis Components
- **`test_dataflow_analyzer.py`** - CrossFileDataflowAnalyzer tests
- **`test_threat_mapper.py`** - ThreatMapper and taxonomy tests

## Running Tests

```bash
# Run all behavioral tests
pytest tests/behavioral/

# Run specific component tests
pytest tests/behavioral/test_code_analyzer.py
pytest tests/behavioral/test_threat_mapper.py

# Run with coverage
pytest tests/behavioral/ --cov=mcpscanner.core.analyzers.behavioral

# Run with verbose output
pytest tests/behavioral/ -v
```

## Test Coverage

Current test coverage focuses on:
- ✅ Component initialization and imports
- ✅ Threat taxonomy validation (9 categories)
- ✅ Module structure verification
- ✅ Basic functionality tests

### Areas Needing More Coverage
- ⚠️ LLM integration with mocked responses
- ⚠️ Dataflow tracking across files
- ⚠️ Complete end-to-end analysis workflows
- ⚠️ Error handling and edge cases

## Contributing

When adding new tests:
1. Follow the existing naming convention: `test_<component_name>.py`
2. Include copyright header and SPDX identifier
3. Use descriptive test names: `test_<what_is_being_tested>`
4. Add docstrings to test classes and methods
5. Update this README with new test categories
