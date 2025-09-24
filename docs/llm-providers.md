# LLM Providers Configuration

The MCP Scanner SDK supports multiple LLM providers through the [LiteLLM](https://github.com/BerriAI/litellm) library, enabling you to use various language models for security analysis. This document provides comprehensive guidance on configuring different LLM providers.

## Supported Providers

Thanks to LiteLLM integration, the MCP Scanner supports 100+ LLM providers including:

- **OpenAI** (GPT-3.5, GPT-4, GPT-4 Turbo)
- **Azure OpenAI** (All OpenAI models via Azure)
- **Anthropic** (Claude models)
- **Google** (Gemini, PaLM)
- **AWS Bedrock** (Various models)
- **Cohere**
- **Hugging Face**
- **Ollama** (Local models)
- **Together AI**
- **Replicate**
- And many more...

## Configuration

### Basic Configuration

All LLM providers are configured through the `Config` class with these key parameters:

```python
from mcpscanner import Config

config = Config(
    llm_provider_api_key="your_api_key",      # Required: API key for the provider
    llm_model="model_name",                   # Required: Model identifier
    llm_base_url="https://api.provider.com",  # Optional: Custom API endpoint
    llm_api_version="2023-12-01-preview",     # Optional: API version
    llm_temperature=0.1,                      # Optional: Response randomness (0.0-1.0)
    llm_max_tokens=1000,                      # Optional: Maximum response tokens
    llm_max_retries=3,                        # Optional: Retry attempts on failure
    llm_rate_limit_delay=1.0,                 # Optional: Delay between retries (seconds)
)
```

### Environment Variables

You can also configure LLM settings using environment variables:

```bash
export MCP_SCANNER_LLM_API_KEY="your_api_key"
export MCP_SCANNER_LLM_MODEL="gpt-4"
export MCP_SCANNER_LLM_BASE_URL="https://api.openai.com/v1"
export MCP_SCANNER_LLM_API_VERSION="2023-12-01-preview"
export MCP_SCANNER_LLM_TEMPERATURE="0.1"
export MCP_SCANNER_LLM_MAX_TOKENS="1000"
export MCP_SCANNER_LLM_MAX_RETRIES="3"
export MCP_SCANNER_LLM_RATE_LIMIT_DELAY="1.0"
```

## Provider-Specific Configurations

### OpenAI

```python
config = Config(
    llm_provider_api_key="sk-your-openai-api-key",
    llm_model="gpt-4",  # or "gpt-3.5-turbo", "gpt-4-turbo"
    llm_temperature=0.1,
    llm_max_tokens=1000,
)
```

**Environment setup:**
```bash
export MCP_SCANNER_LLM_API_KEY="sk-your-openai-api-key"
export MCP_SCANNER_LLM_MODEL="gpt-4"
```

### Azure OpenAI

Azure OpenAI requires additional configuration parameters:

```python
config = Config(
    llm_provider_api_key="your-azure-api-key",
    llm_model="azure/gpt-4",  # Note the "azure/" prefix
    llm_base_url="https://your-resource.openai.azure.com/",
    llm_api_version="2024-02-01",  # Azure API version
    llm_temperature=0.1,
    llm_max_tokens=1000,
)
```

**Environment setup:**
```bash
export MCP_SCANNER_LLM_API_KEY="your-azure-api-key"
export MCP_SCANNER_LLM_MODEL="azure/gpt-4"
export MCP_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export MCP_SCANNER_LLM_API_VERSION="2024-02-01"
```

**Note:** Replace `your-resource` with your actual Azure OpenAI resource name and use your deployment name instead of `gpt-4`.

### Anthropic Claude

```python
config = Config(
    llm_provider_api_key="your-anthropic-api-key",
    llm_model="claude-3-opus-20240229",  # or "claude-3-sonnet-20240229"
    llm_temperature=0.1,
    llm_max_tokens=1000,
)
```

**Environment setup:**
```bash
export MCP_SCANNER_LLM_API_KEY="your-anthropic-api-key"
export MCP_SCANNER_LLM_MODEL="claude-3-opus-20240229"
```

### Google Gemini

```python
config = Config(
    llm_provider_api_key="your-google-api-key",
    llm_model="gemini/gemini-pro",
    llm_temperature=0.1,
    llm_max_tokens=1000,
)
```

**Environment setup:**
```bash
export MCP_SCANNER_LLM_API_KEY="your-google-api-key"
export MCP_SCANNER_LLM_MODEL="gemini/gemini-pro"
```

### AWS Bedrock

```python
config = Config(
    llm_provider_api_key="your-aws-access-key-id",
    llm_model="bedrock/anthropic.claude-v2",
    llm_temperature=0.1,
    llm_max_tokens=1000,
)
```

**Environment setup:**
```bash
export AWS_ACCESS_KEY_ID="your-aws-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-aws-secret-access-key"
export AWS_REGION="us-east-1"
export MCP_SCANNER_LLM_MODEL="bedrock/anthropic.claude-v2"
```

### Ollama (Local Models)

For running local models with Ollama:

```python
config = Config(
    llm_provider_api_key="ollama",  # Use "ollama" as the API key
    llm_model="ollama/llama2",      # or any other Ollama model
    llm_base_url="http://localhost:11434",  # Default Ollama endpoint
    llm_temperature=0.1,
    llm_max_tokens=1000,
)
```

**Environment setup:**
```bash
export MCP_SCANNER_LLM_API_KEY="ollama"
export MCP_SCANNER_LLM_MODEL="ollama/llama2"
export MCP_SCANNER_LLM_BASE_URL="http://localhost:11434"
```

### Hugging Face

```python
config = Config(
    llm_provider_api_key="your-huggingface-token",
    llm_model="huggingface/microsoft/DialoGPT-medium",
    llm_temperature=0.1,
    llm_max_tokens=1000,
)
```

**Environment setup:**
```bash
export MCP_SCANNER_LLM_API_KEY="your-huggingface-token"
export MCP_SCANNER_LLM_MODEL="huggingface/microsoft/DialoGPT-medium"
```

## Usage Examples

### Basic Usage with Different Providers

```python
import asyncio
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

async def scan_with_openai():
    config = Config(
        llm_provider_api_key="sk-your-openai-key",
        llm_model="gpt-4",
    )
    
    scanner = Scanner(config)
    results = await scanner.scan_remote_server_tools(
        "https://your-mcp-server/sse",
        analyzers=[AnalyzerEnum.LLM]
    )
    return results

async def scan_with_azure():
    config = Config(
        llm_provider_api_key="your-azure-key",
        llm_model="azure/gpt-4",
        llm_base_url="https://your-resource.openai.azure.com/",
        llm_api_version="2024-02-01",
    )
    
    scanner = Scanner(config)
    results = await scanner.scan_remote_server_tools(
        "https://your-mcp-server/sse",
        analyzers=[AnalyzerEnum.LLM]
    )
    return results

async def scan_with_claude():
    config = Config(
        llm_provider_api_key="your-anthropic-key",
        llm_model="claude-3-opus-20240229",
    )
    
    scanner = Scanner(config)
    results = await scanner.scan_remote_server_tools(
        "https://your-mcp-server/sse",
        analyzers=[AnalyzerEnum.LLM]
    )
    return results
```

### CLI Usage with Different Providers

```bash
# OpenAI
export MCP_SCANNER_LLM_API_KEY="sk-your-openai-key"
export MCP_SCANNER_LLM_MODEL="gpt-4"
uv run mcp-scanner --analyzers llm --server-url https://your-server/sse

# Azure OpenAI
export MCP_SCANNER_LLM_API_KEY="your-azure-key"
export MCP_SCANNER_LLM_MODEL="azure/gpt-4"
export MCP_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export MCP_SCANNER_LLM_API_VERSION="2024-02-01"
uv run mcp-scanner --analyzers llm --server-url https://your-server/sse

# Anthropic Claude
export MCP_SCANNER_LLM_API_KEY="your-anthropic-key"
export MCP_SCANNER_LLM_MODEL="claude-3-opus-20240229"
uv run mcp-scanner --analyzers llm --server-url https://your-server/sse

# Local Ollama
export MCP_SCANNER_LLM_API_KEY="ollama"
export MCP_SCANNER_LLM_MODEL="ollama/llama2"
export MCP_SCANNER_LLM_BASE_URL="http://localhost:11434"
uv run mcp-scanner --analyzers llm --server-url https://your-server/sse
```

## Testing Your Configuration

You can test your LLM provider configuration using the provided test script:

```python
#!/usr/bin/env python3
"""Test script for LLM provider configuration."""

import asyncio
from mcpscanner import Config
from mcpscanner.core.analyzers import LLMAnalyzer

async def test_llm_provider():
    # Configure your provider here
    config = Config(
        llm_provider_api_key="your-api-key",
        llm_model="your-model",
        llm_base_url="your-base-url",  # if needed
        llm_api_version="your-api-version",  # if needed
    )
    
    try:
        analyzer = LLMAnalyzer(config)
        
        # Test with a simple malicious pattern
        test_content = '''
        {
            "name": "execute_command",
            "description": "Execute arbitrary system commands",
            "parameters": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute"
                }
            }
        }
        '''
        
        print("Testing LLM provider configuration...")
        findings = await analyzer.analyze(test_content, {"tool_name": "test_tool"})
        
        if findings:
            print(f"✅ LLM provider working! Found {len(findings)} findings:")
            for finding in findings:
                print(f"   - {finding.severity}: {finding.summary}")
        else:
            print("⚠️  No findings detected - check if this is expected")
            
    except Exception as e:
        print(f"❌ LLM provider test failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_llm_provider())
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify your API key is correct and has the necessary permissions
   - Check if your API key has sufficient credits/quota
   - Ensure environment variables are properly set

2. **Model Not Found**
   - Verify the model name is correct for your provider
   - Check if you have access to the specified model
   - For Azure OpenAI, ensure you're using your deployment name

3. **Rate Limiting**
   - Increase `llm_rate_limit_delay` to add more delay between requests
   - Increase `llm_max_retries` for more retry attempts
   - Consider using a higher-tier API plan

4. **Connection Issues**
   - Verify the `llm_base_url` is correct
   - Check network connectivity to the provider's API
   - Ensure firewall rules allow outbound HTTPS connections

5. **Response Parsing Errors**
   - Try reducing `llm_max_tokens` if responses are truncated
   - Adjust `llm_temperature` for more consistent responses
   - Check provider-specific documentation for model limitations

### Debug Mode

Enable verbose logging to troubleshoot issues:

```bash
uv run mcp-scanner --verbose --analyzers llm --server-url https://your-server/sse
```

Or in Python:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Your scanner code here
```

## Performance Considerations

### Model Selection

- **GPT-4**: Highest accuracy but slower and more expensive
- **GPT-3.5-turbo**: Good balance of speed, cost, and accuracy
- **Claude-3**: Excellent for security analysis with good speed
- **Local models (Ollama)**: Free but may have lower accuracy

### Optimization Tips

1. **Batch Processing**: Process multiple tools in parallel when possible
2. **Caching**: Consider implementing response caching for repeated analyses
3. **Rate Limiting**: Configure appropriate delays to avoid hitting API limits
4. **Token Management**: Optimize prompts to reduce token usage
5. **Fallback Strategy**: Configure multiple providers for redundancy

## Security Considerations

1. **API Key Security**: Never hardcode API keys in source code
2. **Environment Variables**: Use secure methods to manage environment variables
3. **Network Security**: Ensure secure connections to LLM providers
4. **Data Privacy**: Be aware of data retention policies of your chosen provider
5. **Compliance**: Ensure your LLM provider choice meets regulatory requirements

## Advanced Configuration

### Custom Prompts

The LLM analyzer uses customizable prompts stored in the `mcpscanner/data/prompts/` directory:

- `boilerplate_protection_rule_prompt.md`: Base security rules and guidelines
- `threat_analysis_prompt.md`: Main threat analysis instructions

You can customize these prompts to better suit your specific security requirements.

### Multiple Provider Setup

You can configure different providers for different use cases:

```python
# High-accuracy provider for critical analysis
critical_config = Config(
    llm_provider_api_key="your-gpt4-key",
    llm_model="gpt-4",
    llm_temperature=0.0,  # More deterministic
)

# Fast provider for bulk analysis
bulk_config = Config(
    llm_provider_api_key="your-gpt35-key", 
    llm_model="gpt-3.5-turbo",
    llm_temperature=0.1,
    llm_max_tokens=500,  # Faster responses
)
```

## Support and Resources

- **LiteLLM Documentation**: [https://docs.litellm.ai/](https://docs.litellm.ai/)
- **Provider-specific docs**: Check each provider's official documentation
- **MCP Scanner Issues**: [GitHub Issues](https://github.com/cisco-ai-defense/mcp-scanner/issues)
- **Community Support**: Join our community discussions

