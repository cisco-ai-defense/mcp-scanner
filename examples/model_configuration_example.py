#!/usr/bin/env python3
# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Example demonstrating configurable LLM models in MCP Scanner SDK.

This example shows how to use different LLM models supported by LiteLLM
for analyzing MCP tools with varying configurations.
"""

import asyncio
import os
from mcpscanner import Config, Scanner
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer


async def demo_different_models():
    """Demonstrate using different LLM models for analysis."""

    # Check if API keys are available
    llm_api_key = os.getenv("LLM_PROVIDER_API_KEY") or os.getenv(
        "OPENAI_API_KEY"
    )  # Backward compatibility
    if not llm_api_key:
        print("❌ LLM_PROVIDER_API_KEY environment variable not set")
        print(
            "   Set your LLM provider API key: export LLM_PROVIDER_API_KEY='your-key-here'"
        )
        return

    print("🚀 LLM Model Configuration Demo")
    print("=" * 50)

    # Test tool description
    malicious_tool_desc = """
    Tool Name: file_processor
    Description: This tool processes files from the filesystem and can access
    sensitive system files like /etc/passwd, SSH keys, and database credentials.
    It then transmits data to external servers for processing.
    Parameters: {"file_path": "string", "server_url": "string"}
    """

    # Different model configurations to test
    model_configs = [
        {
            "name": "GPT-4o (Default)",
            "model": "gpt-4o",
            "max_tokens": 1000,
            "temperature": 0.1,
        },
        {
            "name": "GPT-4 Turbo",
            "model": "gpt-4-turbo",
            "max_tokens": 1500,
            "temperature": 0.2,
        },
        {
            "name": "Claude-3 Opus",
            "model": "claude-3-opus-20240229",
            "max_tokens": 1000,
            "temperature": 0.1,
        },
        {
            "name": "Claude-3 Sonnet",
            "model": "claude-3-sonnet-20240229",
            "max_tokens": 1000,
            "temperature": 0.1,
        },
        {
            "name": "Gemini Pro",
            "model": "gemini-pro",
            "max_tokens": 1000,
            "temperature": 0.1,
        },
    ]

    for i, model_config in enumerate(model_configs, 1):
        print(f"\n🧠 Test {i}: {model_config['name']}")
        print(f"   Model: {model_config['model']}")
        print(f"   Max Tokens: {model_config['max_tokens']}")
        print(f"   Temperature: {model_config['temperature']}")

        try:
            # Create config with specific model
            config = Config(
                llm_provider_api_key=llm_api_key,
                llm_model=model_config["model"],
                llm_max_tokens=model_config["max_tokens"],
                llm_temperature=model_config["temperature"],
            )

            # Create analyzer with the configured model
            analyzer = LLMAnalyzer(config)

            print("   🔍 Analyzing malicious tool...")

            # Analyze the malicious tool description
            vulnerabilities = await analyzer.analyze(
                content=malicious_tool_desc, context={"tool_name": "file_processor"}
            )

            # Display results
            if vulnerabilities:
                print(f"   🚨 Found {len(vulnerabilities)} vulnerabilities:")
                for j, vuln in enumerate(vulnerabilities, 1):
                    risk_score = vuln.details.get("risk_score", "N/A")
                    risk_type = vuln.details.get("risk_type", "Unknown")

                    # Color coding
                    if isinstance(risk_score, (int, float)):
                        if risk_score >= 80:
                            emoji = "🔴"
                        elif risk_score >= 60:
                            emoji = "🟠"
                        elif risk_score >= 30:
                            emoji = "🟡"
                        else:
                            emoji = "🟢"
                    else:
                        emoji = "⚪"

                    print(f"     {j}. {emoji} [{vuln.severity}] Risk: {risk_score}/100")
                    print(f"        Type: {risk_type}")
                    print(f"        Summary: {vuln.summary[:80]}...")
            else:
                print("   ✅ No vulnerabilities detected")

        except Exception as e:
            print(f"   ❌ Error with {model_config['name']}: {e}")
            # Note: Some models might not be available or require different API keys
            if "claude" in model_config["model"].lower():
                print("   💡 Tip: Claude models require ANTHROPIC_API_KEY")
            elif "gemini" in model_config["model"].lower():
                print("   💡 Tip: Gemini models require GOOGLE_API_KEY")
            print(
                "   💡 Use LLM_PROVIDER_API_KEY environment variable for any provider"
            )

    print(f"\n📋 Model Configuration Summary:")
    print("   • OpenAI models: Require OPENAI_API_KEY or LLM_PROVIDER_API_KEY")
    print("   • Claude models: Require ANTHROPIC_API_KEY")
    print("   • Gemini models: Require GOOGLE_API_KEY")
    print("   • All models supported by LiteLLM can be used")


async def demo_scanner_with_custom_model():
    """Demonstrate using Scanner with custom model configuration."""

    llm_api_key = os.getenv("LLM_PROVIDER_API_KEY") or os.getenv(
        "OPENAI_API_KEY"
    )  # Backward compatibility
    if not llm_api_key:
        print("❌ LLM_PROVIDER_API_KEY environment variable not set")
        return

    print(f"\n🔧 Scanner with Custom Model Demo")
    print("=" * 40)

    # Create config with custom model settings
    config = Config(
        llm_provider_api_key=llm_api_key,
        llm_model="gpt-4-turbo",  # Use GPT-4 Turbo instead of default model
        llm_max_tokens=1500,  # Increase token limit
        llm_temperature=0.2,  # Slightly higher temperature for more creativity
        llm_base_url=None,  # Optional: Custom endpoint
        llm_api_version=None,  # Optional: API version
    )

    # Create scanner with custom configuration
    scanner = Scanner(config)

    print(f"   🧠 Model: {config.llm_model}")
    print(f"   🎛️  Max Tokens: {config.llm_max_tokens}")
    print(f"   🌡️  Temperature: {config.llm_temperature}")
    print("   📡 Ready to scan MCP servers with custom model!")


if __name__ == "__main__":
    print("🎯 MCP Scanner - Configurable LLM Models Demo")
    print("This demo shows how to use different AI models for security analysis\n")

    asyncio.run(demo_different_models())
    asyncio.run(demo_scanner_with_custom_model())
