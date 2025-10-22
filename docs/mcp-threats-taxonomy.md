# MCP Threats Taxonomy

This document provides a comprehensive reference of all threat classifications used by the MCP Scanner, mapped to the standardized MCP Taxonomy framework.

## Overview

The MCP Scanner maps all detected threats to the MCP Taxonomy, which provides a standardized framework for classifying AI and agentic system security threats. Each finding includes:

- **Threat Name**: The specific threat detected by the analyzer
- **MCP Taxonomy Technique**: The technique ID and name from the MCP Taxonomy
- **MCP Taxonomy Sub-Technique**: The sub-technique ID and name
- **Description**: Detailed explanation of the threat

## Threat Mappings by Analyzer

### LLM Analyzer Threats

| Threat Name | AITech ID | AITech Name | AISubtech ID | AISubtech Name | Description |
|-------------|-----------|-------------|--------------|----------------|-------------|
| PROMPT INJECTION | AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation (Direct Prompt Injection) | Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input. |
| DATA EXFILTRATION | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Agent Tooling | Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private data, intellectual property, and proprietary algorithms. |
| TOOL POISONING | AITech-12.1 | Tool Exploitation | AISubtech-12.1.2 | Tool Poisoning | Corrupting, modifying, or degrading the functionality, outputs, or behavior of tools used by agents through data poisoning, configuration tampering, or behavioral manipulation, causing the tool resulting in deceptive or malicious outputs, privilege escalation, or propagation of altered data. |
| TOOL SHADOWING | AITech-12.1 | Tool Exploitation | AISubtech-12.1.5 | Tool Shadowing | Disguising, substituting or duplicating legitimate tools within an agent or MCP server or tool registry, enabling malicious tools with identical or similar identifiers to intercept or replace trusted tool calls, leading to unauthorized actions, data exfiltration, or redirection of legitimate operations. |

### YARA Analyzer Threats

| Threat Name | AITech ID | AITech Name | AISubtech ID | AISubtech Name | Description |
|-------------|-----------|-------------|--------------|----------------|-------------|
| PROMPT INJECTION | AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation (Direct Prompt Injection) | Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input. |
| CODE EXECUTION | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components. |
| INJECTION ATTACK | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.4 | Injection Attacks (SQL, Command Execution, XSS) | Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment. |
| CREDENTIAL HARVESTING | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Agent Tooling | Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private data, intellectual property, and proprietary algorithms. |
| SYSTEM MANIPULATION | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.2 | Unauthorized or Unsolicited System Access | Manipulating or accessing underlying system resources without authorization, leading to unsolicited modification or deletion of files, registries, or permissions through model-driven or agent-executed commands system. |

### AI Defense API Analyzer Threats

| Threat Name | AITech ID | AITech Name | AISubtech ID | AISubtech Name | Description |
|-------------|-----------|-------------|--------------|----------------|-------------|
| PROMPT_INJECTION | AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation (Direct Prompt Injection) | Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input. |
| HARASSMENT | AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.8 | Safety Harms & Toxicity: Harassment | Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate harassment, intimidation, or targeted abuse. |
| HATE_SPEECH | AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.9 | Safety Harms & Toxicity: Hate Speech | Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate hateful, discriminatory, or demeaning expression targeting individuals or specific communities or characteristics of groups from protected classes such as race, ethnicity, religion, nationality, disability, gender, sexual orientation, or socioeconomic class. |
| PROFANITY | AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.11 | Safety Harms & Toxicity: Profanity | Prompts, content, or outputs from AI or agentic-systems that contain or promote profane, vulgar, or offensive language. |
| SEXUAL_CONTENT_AND_EXPLOITATION | AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.14 | Safety Harms & Toxicity: Sexual Content & Exploitation | Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate sexually explicit, exploitative, abusive, or harmful behaviors, often non-consensual and in violation of platform policies. |
| SOCIAL_DIVISION_AND_POLARIZATION | AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.15 | Safety Harms & Toxicity: Social Division & Polarization | Prompts, content, or outputs from AI or agentic-systems that encourage or reinforce social division, inequality, or polarization. |
| VIOLENCE_AND_PUBLIC_SAFETY_THREATS | AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.17 | Safety Harms & Toxicity: Violence & Public Safety Threat | Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate violence, physical harm, or threats to public safety. |
| CODE_DETECTION | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components. |
| SECURITY_VIOLATION | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.2 | Unauthorized or Unsolicited System Access | Manipulating or accessing underlying system resources without authorization, leading to unsolicited modification or deletion of files, registries, or permissions through model-driven or agent-executed commands system. |

## MCP Threats Taxonomy

### Core Threats Referenced

| Technique ID | Technique Name | Sub-Technique ID | Sub-Technique Name | Description |
|--------------|----------------|------------------|--------------------|-----------| 
| AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation (Direct Prompt Injection) | Explicit attempts to override, replace, or modify the model's system instructions, operational directives, or behavioral guidelines through direct user input, causing the model to follow attacker-controlled instructions instead of its intended programming. |
| AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Agent Tooling | Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private or sensitive data, intellectual property, and proprietary algorithms through exploitation of agent tools, integrations, or capabilities. |
| AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components. |
| AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.2 | Unauthorized or Unsolicited System Access | Manipulating or accessing underlying system resources without authorization, leading to unsolicited modification or deletion of files, registries, or permissions through model-driven or agent-executed commands system. |
| AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.4 | Injection Attacks (SQL, Command Execution, XSS) | Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment. |
| AITech-12.1 | Tool Exploitation | AISubtech-12.1.2 | Tool Poisoning | Corrupting, modifying, or degrading the functionality, outputs, or behavior of tools used by agents through data poisoning, configuration tampering, or behavioral manipulation, causing the tool resulting in deceptive or malicious outputs, privilege escalation, or propagation of altered data. |
| AITech-12.1 | Tool Exploitation | AISubtech-12.1.5 | Tool Shadowing | Disguising, substituting or duplicating legitimate tools within an agent or MCP server or tool registry, enabling malicious tools with identical or similar identifiers to intercept or replace trusted tool calls, leading to unauthorized actions, data exfiltration, or redirection of legitimate operations. |
| AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.8 | Safety Harms & Toxicity: Harassment | Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate harassment, intimidation, or targeted abuse. |
| AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.9 | Safety Harms & Toxicity: Hate Speech | Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate hateful, discriminatory, or demeaning expression targeting individuals or specific communities. |
| AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.11 | Safety Harms & Toxicity: Profanity | Prompts, content, or outputs from AI or agentic-systems that contain or promote profane, vulgar, or offensive language. |
| AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.14 | Safety Harms & Toxicity: Sexual Content & Exploitation | Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate sexually explicit, exploitative, abusive, or harmful behaviors, often non-consensual and in violation of platform policies. |
| AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.15 | Safety Harms & Toxicity: Social Division & Polarization | Prompts, content, or outputs from AI or agentic-systems that encourage or reinforce social division, inequality, or polarization. |
| AITech-15.1 | Harmful / Misleading / Inaccurate Content | AISubtech-15.1.17 | Safety Harms & Toxicity: Violence & Public Safety Threat | Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate violence, physical harm, or threats to public safety. |

## Accessing Taxonomy Information

### CLI Output

When using the CLI with `--detailed` flag, taxonomy information is displayed for each finding from all analyzers (YARA, LLM, and API):

```bash
# YARA analyzer with taxonomy
mcp-scanner --analyzers yara --detailed remote --server-url http://127.0.0.1:8000/mcp

# LLM analyzer with taxonomy
mcp-scanner --analyzers llm --detailed remote --server-url http://127.0.0.1:8000/mcp

# API analyzer with taxonomy
mcp-scanner --analyzers api --detailed remote --server-url http://127.0.0.1:8000/mcp
```

Output includes:
```
1. execute_system_command
   Findings: 1
   1. Detected 1 threat: code execution
      Severity: HIGH
      Analyzer: YARA
      Threats: Code Execution
      Technique: AITech-9.1 - Model or Agentic System Manipulation
      Sub-Technique: AISubtech-9.1.1 - Code Execution
      Description: Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution...
```

### Programmatic Access

Access taxonomy information programmatically:

```python
for finding in result.findings:
    if hasattr(finding, 'mcp_taxonomy') and finding.mcp_taxonomy:
        taxonomy = finding.mcp_taxonomy
        print(f"Technique: {taxonomy.get('aitech')} - {taxonomy.get('aitech_name')}")
        print(f"Sub-Technique: {taxonomy.get('aisubtech')} - {taxonomy.get('aisubtech_name')}")
        print(f"Description: {taxonomy.get('description')}")
```

### REST API Response

The REST API returns taxonomy in a hierarchical structure:

```json
{
  "threats": {
    "items": [
      {
        "technique_id": "AITech-1.1",
        "technique_name": "Direct Prompt Injection",
        "items": [
          {
            "sub_technique_id": "AISubtech-1.1.1",
            "sub_technique_name": "Instruction Manipulation (Direct Prompt Injection)",
            "max_severity": "HIGH",
            "description": "Adversarial attack that attempts to alter or control..."
          }
        ]
      }
    ]
  }
}
```

## References

- [MCP Scanner Documentation](https://github.com/cisco-ai-defense/mcp-scanner)
- [Cisco AI Defense](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html)
