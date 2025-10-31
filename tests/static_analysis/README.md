# Static Analysis Tests

This directory contains tests for the static analysis components used by the Behavioral Code Analyzer.

## Test Structure

Tests are organized by static analysis component:

### Core Components
- **`test_context_extractor.py`** - Tests for code context extraction and AST parsing
- **`test_parser.py`** - Tests for Python parser and AST utilities

### Analysis Components
- **`test_cfg.py`** - Tests for Control Flow Graph (CFG) construction
- **`test_dataflow.py`** - Tests for dataflow analysis and parameter tracking
- **`test_taint.py`** - Tests for taint analysis
- **`test_semantic.py`** - Tests for semantic analysis
- **`test_types.py`** - Tests for type inference
- **`test_interprocedural.py`** - Tests for cross-function analysis

## Component Overview

### Context Extractor (`context_extractor.py`)
Extracts comprehensive information about MCP entry points:
- Detects `@mcp.tool()`, `@mcp.resource()`, `@mcp.prompt()` decorators
- Extracts function metadata (parameters, return types, docstrings)
- Builds function context for analysis

### Dataflow Analysis (`dataflow/`)
Tracks how data flows through the code:
- Parameter flow tracking
- Variable assignments and transformations
- External operation detection (file, network, subprocess)

### CFG (`cfg/`)
Builds Control Flow Graphs:
- Statement-level control flow
- Branch and loop detection
- Reachability analysis

### Taint Analysis (`taint/`)
Tracks tainted (untrusted) data:
- Source identification (user inputs)
- Sink detection (dangerous operations)
- Propagation through transformations

### Parser (`parser/`)
Python AST parsing utilities:
- AST node traversal
- Pattern matching
- Code structure extraction

### Semantic Analysis (`semantic/`)
Higher-level code understanding:
- Function call resolution
- Import tracking
- Symbol resolution

### Type Inference (`types/`)
Static type analysis:
- Type propagation
- Type constraints
- Type checking

### Interprocedural Analysis (`interprocedural/`)
Cross-function analysis:
- Call graph construction
- Inter-procedural dataflow
- Cross-file tracking

## Running Tests

```bash
# Run all static analysis tests
pytest tests/static_analysis/

# Run specific component tests
pytest tests/static_analysis/test_dataflow.py
pytest tests/static_analysis/test_context_extractor.py

# Run with coverage
pytest tests/static_analysis/ --cov=mcpscanner.core.static_analysis

# Run with verbose output
pytest tests/static_analysis/ -v
```

## Relationship to Behavioral Analyzer

The static analysis components are foundational building blocks used by the Behavioral Code Analyzer:

```
BehavioralCodeAnalyzer
    ↓
Uses: context_extractor.py (extract MCP functions)
    ↓
Uses: dataflow/ (track parameter flows)
    ↓
Uses: semantic/ (resolve imports and calls)
    ↓
Feeds data to: AlignmentOrchestrator (LLM analysis)
```

## Contributing

When adding new tests:
1. Match the test file name to the component: `test_<component_name>.py`
2. Include copyright header and SPDX identifier
3. Use descriptive test class and method names
4. Test both happy paths and edge cases
5. Mock external dependencies when needed
6. Update this README with new test categories
