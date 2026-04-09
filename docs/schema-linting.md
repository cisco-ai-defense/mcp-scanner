# MCP Schema Linting

The `lint` subcommand validates MCP tool, prompt, and resource schemas for quality, completeness, and consistency. It surfaces issues early — before runtime or security scanning — using a rule-driven validation model.

## Quick Start

```bash
# Lint a remote MCP server
mcp-scanner lint --server-url https://mcp.deepwiki.com/mcp

# Lint a stdio server
mcp-scanner lint --stdio-command "npx -y @example/mcp-server"

# Lint from static JSON files (offline)
mcp-scanner lint --tools-file tools.json
mcp-scanner lint --tools-file tools.json --prompts-file prompts.json

# Use a stricter ruleset
mcp-scanner lint --server-url https://mcp.example.com/mcp --ruleset strict

# JSON output for CI/CD
mcp-scanner lint --server-url https://mcp.example.com/mcp --format json
```

## Output Formats

### Table (default)

```
Tool Quality
    #  SEVERITY  CODE                                 FINDINGS                        RECOMMENDATION                                 AFFECTED ITEMS
    1  info      tool-schema-has-examples             Tool 'read_wiki_structure'      Add 'example' field to properties for better          3
                                                      properties missing examples:    documentation
                                                      repoName
    2  info      tool-output-schema-defined           Tool 'read_wiki_structure' has  Add an outputSchema to define the structure           3
                                                      no outputSchema defined         of tool results
2 Findings (0 Error, 0 Warning, 2 Info, 0 Hint)
  # | CATEGORY     | ERROR | WARNING | INFO | HINT
  -----------------------------------------------------------
  1 | Tool         |     0 |       0 |    6 |    0

============================================================
Summary
  Scanned:       3 tools
  Rules checked: 37
  Rules passed:  35 (94%)
  Rules failed:  2
  Total issues:  6
```

### Summary

A compact overview of scanned items, rules checked, and issue counts.

### JSON

Machine-readable output for CI/CD pipelines:

```json
{
  "target": "https://mcp.example.com/mcp",
  "tools_scanned": 3,
  "prompts_scanned": 0,
  "resources_scanned": 0,
  "rules_checked": 37,
  "rules_passed": 35,
  "rules_failed": 2,
  "total_findings": 6,
  "findings_by_severity": {"info": 6},
  "findings_by_category": {"tool": 6},
  "findings": [
    {
      "rule_id": "tool-schema-has-examples",
      "severity": "info",
      "category": "tool",
      "message": "Tool 'read_wiki_structure' properties missing examples: repoName",
      "recommendation": "Add 'example' field to properties for better documentation",
      "item_name": "read_wiki_structure",
      "affected_items": 1,
      "location": "inputSchema.properties"
    }
  ]
}
```

## Built-in Rules (37)

### Tool Rules (18)

| ID | Default Severity | Description |
|----|-----------------|-------------|
| `tool-has-name` | error | Tool must have a non-empty name |
| `tool-has-description` | warning | Tool must have a description |
| `tool-description-min-length` | info | Description should be at least 20 characters |
| `tool-description-not-name` | warning | Description should not just repeat the name |
| `tool-name-convention` | info | Name should follow snake_case or camelCase |
| `tool-name-max-length` | info | Name should be under 64 characters |
| `tool-has-input-schema` | warning | Tool should define an inputSchema |
| `tool-input-schema-has-properties` | warning | inputSchema should define properties |
| `tool-input-schema-has-required` | info | inputSchema should declare required fields |
| `tool-required-params-defined` | error | Required params must exist in properties |
| `tool-schema-properties-have-types` | warning | Each property should have a type |
| `tool-schema-properties-have-descriptions` | info | Each property should have a description |
| `tool-schema-has-examples` | info | Properties should include examples |
| `tool-output-schema-defined` | info | Tool should define an outputSchema |
| `tool-no-empty-enum` | warning | Enum properties must have values |
| `tool-schema-max-depth` | warning | Schema nesting should not exceed depth 5 |
| `tool-no-duplicate-params` | error | No duplicate property names in schema |
| `tool-description-no-html` | info | Description should not contain HTML tags |

### Prompt Rules (8)

| ID | Default Severity | Description |
|----|-----------------|-------------|
| `prompt-has-name` | error | Prompt must have a non-empty name |
| `prompt-has-description` | warning | Prompt must have a description |
| `prompt-description-min-length` | info | Description should be at least 20 characters |
| `prompt-name-convention` | info | Name should follow a consistent convention |
| `prompt-has-arguments` | info | Prompt should define arguments |
| `prompt-argument-has-description` | info | Each argument should have a description |
| `prompt-argument-has-required` | info | Arguments should specify required flag |
| `prompt-no-duplicate-arguments` | error | No duplicate argument names |

### Resource Rules (6)

| ID | Default Severity | Description |
|----|-----------------|-------------|
| `resource-has-name` | error | Resource must have a non-empty name |
| `resource-has-description` | warning | Resource should have a description |
| `resource-has-mime-type` | warning | Resource should specify a MIME type |
| `resource-mime-type-valid` | warning | MIME type should be valid format |
| `resource-uri-valid` | info | URI should be well-formed |
| `resource-name-convention` | info | Name should follow a consistent convention |

### Server Rules (5)

| ID | Default Severity | Description |
|----|-----------------|-------------|
| `server-has-capabilities` | warning | Server should expose tools, prompts, or resources |
| `server-tool-names-unique` | error | All tool names must be unique |
| `server-prompt-names-unique` | error | All prompt names must be unique |
| `server-resource-uris-unique` | error | All resource URIs must be unique |
| `server-no-excessive-tools` | info | Server should not expose more than 100 tools |

## Rulesets

### `recommended` (default)

All 37 rules at their default severities. Good for everyday development.

### `strict`

All rules enabled with `info` rules promoted to `warning`. Use in CI/CD for stricter enforcement.

### `quality`

Only documentation and completeness rules (descriptions, examples, outputSchema). Use for focused documentation quality checks.

## Configuration

Create a `.mcp-lint.yaml` file to customize rules:

```yaml
extends: recommended
rules:
  tool-output-schema-defined: off
  tool-description-min-length: warning
  tool-schema-has-examples: warning
```

Use it with:

```bash
mcp-scanner lint --server-url <url> --lint-config .mcp-lint.yaml
```

### Override values

- `off` — disable the rule entirely
- `error`, `warning`, `info`, `hint` — override the severity level

## Programmatic Usage

```python
from mcpscanner.core.analyzers.linter import LintEngine, LintFormatter

engine = LintEngine(ruleset="recommended")

tools = [
    {
        "name": "get_user",
        "description": "Fetches a user by ID",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User ID"}
            },
            "required": ["user_id"],
        },
    }
]

summary = engine.lint(tools=tools, target="my-server")

formatter = LintFormatter(summary)
print(formatter.format_table())
print(formatter.format_json())
```

## CI/CD Integration

Use `--format json` and parse the output to fail builds on errors:

```bash
result=$(mcp-scanner lint --server-url "$MCP_URL" --format json)
errors=$(echo "$result" | jq '.findings_by_severity.error // 0')
if [ "$errors" -gt 0 ]; then
  echo "Lint failed with $errors errors"
  exit 1
fi
```
