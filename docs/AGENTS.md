# docs/AGENTS.md

This file provides detailed context for AI coding agents working on **documentation** in the `docs/` directory.

**📁 Parent Guide:** [`../AGENTS.md`](../AGENTS.md) - Global project overview and rules

---

## Overview

The `docs/` directory contains comprehensive documentation covering all aspects of the MCP Scanner, including architecture, usage guides, API references, and development guidelines.

## Documentation Structure

```
docs/
├── architecture.md                        # System design and component interactions
├── behavioral-scanning.md                 # Behavioral analysis deep dive
├── llm-providers.md                       # LLM integration guide
├── mcp-threats-taxonomy.md                # Threat classification system
├── mcp-security-scoring.md                # Security scoring methodology
├── api-reference.md                       # API documentation
├── authentication.md                      # Authentication mechanisms
├── output-formats.md                      # Output format specifications
├── programmatic-usage.md                  # Using scanner as a library
├── programmatic_exception_handling.md     # Error handling guide
├── development.md                         # Development guidelines
└── ... (12 doc files total)
```

## Documentation Categories

### 1. Architecture Documentation

#### `architecture.md`
**Purpose**: Explains system design and component interactions

**Contents**:
- High-level architecture overview
- Component relationships
- Data flow diagrams
- Scanner lifecycle
- Analyzer pipeline
- Extension points

**When to Update**:
- Adding new components
- Changing component interactions
- Modifying data flow
- Adding new scan modes

### 2. Feature Documentation

#### `behavioral-scanning.md`
**Purpose**: Deep dive into behavioral analysis

**Contents**:
- How behavioral analysis works
- LLM-powered semantic analysis
- Description-code mismatch detection
- Context extraction techniques
- Call graph analysis
- False positive mitigation

**When to Update**:
- Changing behavioral analysis logic
- Adding new context extraction features
- Modifying LLM prompts
- Updating false positive guidance

#### `llm-providers.md`
**Purpose**: Guide to LLM integration

**Contents**:
- Supported LLM providers (OpenAI, Azure, Anthropic, Google, AWS Bedrock)
- Configuration for each provider
- Authentication methods
- Model selection guidelines
- Cost considerations
- Rate limiting strategies

**When to Update**:
- Adding new LLM provider support
- Changing authentication methods
- Updating model recommendations
- Adding new configuration options

### 3. Reference Documentation

#### `api-reference.md`
**Purpose**: Complete API documentation

**Contents**:
- Scanner class API
- Analyzer APIs
- Configuration options
- Data models
- Return types
- Error types

**When to Update**:
- Adding new public APIs
- Changing function signatures
- Adding new configuration options
- Modifying return types

#### `mcp-threats-taxonomy.md`
**Purpose**: Threat classification system

**Contents**:
- 14 threat categories
- MITRE-style taxonomy
- Threat descriptions
- Severity levels
- Detection techniques
- Remediation guidance

**When to Update**:
- Adding new threat categories
- Updating threat descriptions
- Changing severity mappings
- Adding detection examples

#### `output-formats.md`
**Purpose**: Output format specifications

**Contents**:
- Available formats (raw, summary, detailed, table, etc.)
- Format structure
- Field descriptions
- Examples
- Custom format creation

**When to Update**:
- Adding new output formats
- Changing format structure
- Adding new fields
- Updating examples

### 4. Usage Documentation

#### `programmatic-usage.md`
**Purpose**: Using scanner as a library

**Contents**:
- Installation instructions
- Basic usage examples
- Advanced usage patterns
- Configuration options
- Best practices
- Performance tips

**When to Update**:
- Adding new scan modes
- Changing API usage patterns
- Adding new configuration options
- Updating best practices

#### `programmatic_exception_handling.md`
**Purpose**: Error handling guide

**Contents**:
- Exception hierarchy
- Common exceptions
- Error handling patterns
- Retry strategies
- Logging best practices
- Debugging tips

**When to Update**:
- Adding new exception types
- Changing error handling behavior
- Adding new error codes
- Updating debugging guidance

#### `authentication.md`
**Purpose**: Authentication mechanisms

**Contents**:
- Bearer token authentication
- API key authentication
- OAuth 2.0 flows
- Custom authentication
- Security best practices

**When to Update**:
- Adding new authentication methods
- Changing authentication flow
- Updating security recommendations
- Adding new examples

### 5. Development Documentation

#### `development.md`
**Purpose**: Development guidelines

**Contents**:
- Development setup
- Code style guidelines
- Testing requirements
- Contribution process
- Release process
- Debugging tips

**When to Update**:
- Changing development workflow
- Adding new tools
- Updating style guidelines
- Modifying contribution process

## Documentation Guidelines

### Writing Style

1. **Clear and Concise**: Use simple language, avoid jargon
2. **Action-Oriented**: Focus on what users need to do
3. **Examples-Heavy**: Include code examples for all concepts
4. **Well-Structured**: Use headings, lists, and tables
5. **Up-to-Date**: Keep documentation synchronized with code

### Formatting Standards

#### Headings
```markdown
# Top-Level Heading (Document Title)
## Major Section
### Subsection
#### Minor Section
```

#### Code Blocks
````markdown
```python
# Always specify language
async def example():
    return "result"
```
````

#### Lists
```markdown
- Use bullet points for unordered lists
- Keep items parallel in structure
- Use consistent punctuation

1. Use numbers for ordered lists
2. Use for sequential steps
3. Keep steps clear and actionable
```

#### Tables
```markdown
| Column 1 | Column 2 | Column 3 |
|----------|----------|----------|
| Value 1  | Value 2  | Value 3  |
```

#### Admonitions
```markdown
**⚠️ WARNING**: Important warning message

**💡 TIP**: Helpful tip or suggestion

**📝 NOTE**: Additional information

**🔒 SECURITY**: Security-related information
```

### Code Examples

#### Good Example
```python
"""
Example: Scanning a remote MCP server

This example demonstrates how to scan a remote MCP server
using the Scanner class with behavioral and LLM analyzers.
"""

import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.config.config import Config

async def main():
    # Configure scanner
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o"
    )
    
    # Create scanner instance
    scanner = Scanner(config)
    
    # Perform scan
    results = await scanner.scan_remote_server(
        server_url="https://example.com/mcp",
        analyzers=["behavioral", "llm"]
    )
    
    # Display results
    print(f"Found {len(results)} findings")

if __name__ == "__main__":
    asyncio.run(main())
```

#### Bad Example
```python
# Don't do this - no context, no comments, unclear
from mcpscanner.core.scanner import Scanner
s = Scanner(c)
r = await s.scan_remote_server(url, ["behavioral"])
```

### Documentation Checklist

When adding or updating documentation:

- [ ] Clear title and purpose statement
- [ ] Table of contents for long documents
- [ ] Code examples with explanations
- [ ] Error handling examples
- [ ] Links to related documentation
- [ ] Prerequisites and requirements
- [ ] Common issues and solutions
- [ ] Last updated date
- [ ] Spell check and grammar check
- [ ] Test all code examples

## Common Documentation Patterns

### Pattern 1: Feature Documentation

```markdown
# Feature Name

## Overview
Brief description of what the feature does and why it's useful.

## How It Works
Detailed explanation of the feature's implementation.

## Usage
### Basic Usage
Simple example showing the most common use case.

### Advanced Usage
More complex examples showing advanced features.

## Configuration
List of configuration options with descriptions.

## Examples
Multiple examples covering different scenarios.

## Troubleshooting
Common issues and solutions.

## Related Documentation
Links to related docs.
```

### Pattern 2: API Documentation

```markdown
# Class/Function Name

## Signature
```python
def function_name(param1: Type1, param2: Type2) -> ReturnType:
    """Brief description"""
```

## Parameters
- `param1` (Type1): Description of param1
- `param2` (Type2): Description of param2

## Returns
ReturnType: Description of return value

## Raises
- `ExceptionType1`: When this exception is raised
- `ExceptionType2`: When this exception is raised

## Examples
```python
# Example usage
result = function_name(value1, value2)
```

## See Also
- Related function/class
```

### Pattern 3: Configuration Documentation

```markdown
# Configuration Option Name

## Environment Variable
`MCP_SCANNER_OPTION_NAME`

## Default Value
`default_value`

## Description
Detailed description of what this option controls.

## Valid Values
- `value1`: Description
- `value2`: Description

## Example
```bash
export MCP_SCANNER_OPTION_NAME=value1
```

## Related Options
- Related option 1
- Related option 2
```

## Updating Documentation

### When Code Changes

1. **New Feature**: Add documentation to relevant files
2. **API Change**: Update `api-reference.md` and usage guides
3. **Configuration Change**: Update configuration documentation
4. **Bug Fix**: Update troubleshooting sections if relevant

### Documentation Review Process

1. **Self-Review**: Check for clarity, completeness, accuracy
2. **Code Review**: Documentation reviewed alongside code changes
3. **User Testing**: Test examples and instructions
4. **Feedback**: Incorporate feedback from users

## Documentation Tools

### Markdown Linting
```bash
# Use markdownlint for consistency
npm install -g markdownlint-cli
markdownlint docs/
```

### Link Checking
```bash
# Check for broken links
npm install -g markdown-link-check
markdown-link-check docs/*.md
```

### Spell Checking
```bash
# Use aspell or similar
aspell check docs/file.md
```

## Common Issues

### Issue 1: Outdated Examples
**Problem**: Code examples don't work with current version
**Solution**: Test all examples when updating code, use CI to validate examples

### Issue 2: Missing Prerequisites
**Problem**: Users can't follow instructions due to missing prerequisites
**Solution**: Always list prerequisites at the beginning of documents

### Issue 3: Unclear Instructions
**Problem**: Users confused by documentation
**Solution**: Test instructions with someone unfamiliar with the code

### Issue 4: Broken Links
**Problem**: Links to other docs or external resources are broken
**Solution**: Use link checker in CI, prefer relative links for internal docs

## Best Practices

1. **Write for Your Audience**: Consider who will read the documentation
2. **Show, Don't Just Tell**: Use examples liberally
3. **Keep It Updated**: Update docs when code changes
4. **Test Your Examples**: Ensure all code examples actually work
5. **Use Consistent Terminology**: Use the same terms throughout
6. **Link Related Content**: Help users discover related information
7. **Include Troubleshooting**: Anticipate common problems
8. **Version Documentation**: Note which version docs apply to

## Contributing Documentation

### Documentation PRs

When submitting documentation changes:

1. **Clear Description**: Explain what you're documenting and why
2. **Test Examples**: Verify all code examples work
3. **Check Links**: Ensure all links are valid
4. **Follow Style Guide**: Use consistent formatting
5. **Update TOC**: Update table of contents if needed
6. **Add Screenshots**: Include screenshots for UI-related docs
7. **Request Review**: Ask for review from someone unfamiliar with the topic

### Documentation Issues

When filing documentation issues:

1. **Specific Location**: Link to the specific doc and section
2. **Clear Problem**: Explain what's unclear or incorrect
3. **Suggested Fix**: Propose how to improve it
4. **Context**: Explain what you were trying to do

## Documentation Metrics

Track documentation quality:

- **Coverage**: Percentage of features documented
- **Freshness**: Time since last update
- **Accuracy**: Number of reported issues
- **Completeness**: Checklist of required sections
- **Usability**: User feedback and questions

## Resources

- **Markdown Guide**: https://www.markdownguide.org/
- **Technical Writing Style Guide**: https://developers.google.com/style
- **Documentation Best Practices**: https://documentation.divio.com/

---

**Last Updated**: December 2025
**Maintained By**: Cisco AI Defense Team
