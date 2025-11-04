# Behavioral Analyzer Configuration

The Behavioral Analyzer supports configurable limits for prompt generation to control the amount of context included in LLM alignment verification requests. These limits can be configured via environment variables.

## Environment Variables

All environment variables are optional and have sensible defaults.

### Prompt Content Limits

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `MCP_SCANNER_BEHAVIORAL_MAX_OPERATIONS_PER_PARAM` | `10` | Maximum number of operations to show per parameter in dataflow analysis |
| `MCP_SCANNER_BEHAVIORAL_MAX_FUNCTION_CALLS` | `20` | Maximum number of function calls to include in the prompt |
| `MCP_SCANNER_BEHAVIORAL_MAX_ASSIGNMENTS` | `15` | Maximum number of variable assignments to show |
| `MCP_SCANNER_BEHAVIORAL_MAX_CROSS_FILE_CALLS` | `10` | Maximum number of cross-file function calls to display |
| `MCP_SCANNER_BEHAVIORAL_MAX_REACHABLE_FILES` | `5` | Maximum number of reachable files to show in reachability analysis |
| `MCP_SCANNER_BEHAVIORAL_MAX_CONSTANTS` | `10` | Maximum number of constants to include |
| `MCP_SCANNER_BEHAVIORAL_MAX_STRING_LITERALS` | `15` | Maximum number of string literals to show |
| `MCP_SCANNER_BEHAVIORAL_MAX_REACHES_CALLS` | `10` | Maximum number of function calls that parameters reach |

## Usage

### Setting Environment Variables

**Linux/macOS:**
```bash
export MCP_SCANNER_BEHAVIORAL_MAX_FUNCTION_CALLS=30
export MCP_SCANNER_BEHAVIORAL_MAX_ASSIGNMENTS=20
```

**Windows (PowerShell):**
```powershell
$env:MCP_SCANNER_BEHAVIORAL_MAX_FUNCTION_CALLS="30"
$env:MCP_SCANNER_BEHAVIORAL_MAX_ASSIGNMENTS="20"
```

**Windows (Command Prompt):**
```cmd
set MCP_SCANNER_BEHAVIORAL_MAX_FUNCTION_CALLS=30
set MCP_SCANNER_BEHAVIORAL_MAX_ASSIGNMENTS=20
```

### Programmatic Configuration

You can also override these limits programmatically when creating an `AlignmentPromptBuilder`:

```python
from mcpscanner.core.analyzers.behavioral.alignment import AlignmentPromptBuilder

# Override specific limits
prompt_builder = AlignmentPromptBuilder(
    max_operations=15,
    max_calls=30,
    max_assignments=20
)
```

## Tuning Guidelines

### When to Increase Limits

- **Large codebases**: Increase limits to capture more context from complex functions
- **Deep call chains**: Increase `MAX_CROSS_FILE_CALLS` and `MAX_REACHABLE_FILES`
- **Complex dataflow**: Increase `MAX_OPERATIONS_PER_PARAM` for detailed parameter tracking

### When to Decrease Limits

- **Token budget concerns**: Reduce limits if hitting LLM token limits
- **Performance optimization**: Lower limits for faster prompt generation
- **Cost reduction**: Smaller prompts = fewer tokens = lower API costs

### Monitoring

The Behavioral Analyzer logs warnings when:
- Prompt length exceeds 50,000 characters
- Large functions are detected (>50KB or >500 lines)
- Large files are processed (>1MB)

Use these logs to tune your limits appropriately.

## Example Configurations

### Minimal Context (Fast, Low Cost)
```bash
export MCP_SCANNER_BEHAVIORAL_MAX_OPERATIONS_PER_PARAM=5
export MCP_SCANNER_BEHAVIORAL_MAX_FUNCTION_CALLS=10
export MCP_SCANNER_BEHAVIORAL_MAX_ASSIGNMENTS=8
export MCP_SCANNER_BEHAVIORAL_MAX_CROSS_FILE_CALLS=5
```

### Maximum Context (Thorough, Higher Cost)
```bash
export MCP_SCANNER_BEHAVIORAL_MAX_OPERATIONS_PER_PARAM=20
export MCP_SCANNER_BEHAVIORAL_MAX_FUNCTION_CALLS=40
export MCP_SCANNER_BEHAVIORAL_MAX_ASSIGNMENTS=30
export MCP_SCANNER_BEHAVIORAL_MAX_CROSS_FILE_CALLS=20
export MCP_SCANNER_BEHAVIORAL_MAX_REACHABLE_FILES=10
```

### Balanced (Default)
```bash
# These are the defaults - no need to set explicitly
# Shown here for reference
export MCP_SCANNER_BEHAVIORAL_MAX_OPERATIONS_PER_PARAM=10
export MCP_SCANNER_BEHAVIORAL_MAX_FUNCTION_CALLS=20
export MCP_SCANNER_BEHAVIORAL_MAX_ASSIGNMENTS=15
export MCP_SCANNER_BEHAVIORAL_MAX_CROSS_FILE_CALLS=10
export MCP_SCANNER_BEHAVIORAL_MAX_REACHABLE_FILES=5
export MCP_SCANNER_BEHAVIORAL_MAX_CONSTANTS=10
export MCP_SCANNER_BEHAVIORAL_MAX_STRING_LITERALS=15
export MCP_SCANNER_BEHAVIORAL_MAX_REACHES_CALLS=10
```
