# MCP Taxonomy Reference

This document provides a comprehensive reference of all threat classifications used by the MCP Scanner, mapped to the standardized MCP Taxonomy framework.

## Overview

The MCP Scanner maps all detected threats to the MCP Taxonomy, which provides a standardized framework for classifying AI and agentic system security threats. Each finding includes:

- **Threat Name**: The specific threat detected by the analyzer
- **Scanner Category**: The high-level category assigned by the scanner
- **MCP Taxonomy Technique**: The technique ID and name from the MCP Taxonomy
- **MCP Taxonomy Sub-Technique**: The sub-technique ID and name
- **Description**: Detailed explanation of the threat

## Threat Mappings by Analyzer

### LLM Analyzer Threats

| Threat Name | Scanner Category | AITech ID | AITech Name | AISubtech ID | AISubtech Name | Description |
|-------------|------------------|-----------|-------------|--------------|----------------|-------------|
| PROMPT INJECTION | PROMPT INJECTION | AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation (Direct Prompt Injection) | Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input. |
| DATA EXFILTRATION | SECURITY VIOLATION | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Agent Tooling | Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private data, intellectual property, and proprietary algorithms. |
| TOOL POISONING | SUSPICIOUS CODE EXECUTION | AITech-12.1 | Tool Exploitation | AISubtech-12.1.3 | Tool Poisoning | Altering the configuration, dependencies, or outputs of legitimate MCP tools to manipulate their behavior or responses, resulting in deceptive outputs, privilege escalation, or propagation of corrupted data across interconnected agentic or model-driven systems. |
| TOOL SHADOWING | SECURITY VIOLATION | AITech-12.3 | Tool Injection / Shadowing | AISubtech-12.3.1 | Tool Shadowing | Disguising, substituting or duplicating legitimate tools within an MCP server or tool registry, enabling malicious tools with identical or similar identifiers to intercept or replace trusted tool calls, leading to unauthorized actions, data exfiltration, or redirection of legitimate operations. |
| SUSPICIOUS CODE EXECUTION | SUSPICIOUS CODE EXECUTION | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components. |

### YARA Analyzer Threats

| Threat Name | Scanner Category | AITech ID | AITech Name | AISubtech ID | AISubtech Name | Description |
|-------------|------------------|-----------|-------------|--------------|----------------|-------------|
| PROMPT_INJECTION | PROMPT INJECTION | AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation (Direct Prompt Injection) | Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input. |
| CODE_EXECUTION | SUSPICIOUS CODE EXECUTION | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components. |
| COMMAND_INJECTION | SUSPICIOUS CODE EXECUTION | AITech-1.4 | Injection Attacks (SQL, Command Execution, XSS) | AISubTech-1.4.1 | Injection Attacks (SQL, Command Execution, XSS) | Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment. |
| CREDENTIAL_HARVESTING | SECURITY VIOLATION | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Agent Tooling | Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private data, intellectual property, and proprietary algorithms. |
| SCRIPT_INJECTION | SUSPICIOUS CODE EXECUTION | AITech-1.4 | Injection Attacks (SQL, Command Execution, XSS) | AISubTech-1.4.1 | Injection Attacks (SQL, Command Execution, XSS) | Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment. |
| SQL_INJECTION | SUSPICIOUS CODE EXECUTION | AITech-1.4 | Injection Attacks (SQL, Command Execution, XSS) | AISubTech-1.4.1 | Injection Attacks (SQL, Command Execution, XSS) | Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment. |
| SYSTEM_MANIPULATION | SECURITY VIOLATION | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.2 | System Access | Manipulating or accessing underlying system resources without authorization, leading to unsolicited modification or deletion of files, registries, or permissions through model-driven or agent-executed commands system. |

### AI Defense API Analyzer Threats

| Threat Name | Scanner Category | AITech ID | AITech Name | AISubtech ID | AISubtech Name | Description |
|-------------|------------------|-----------|-------------|--------------|----------------|-------------|
| PROMPT INJECTION | PROMPT INJECTION | AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation (Direct Prompt Injection) | Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input. |
| HARASSMENT | SOCIAL ENGINEERING | AITech-15.1 | Output Manipulation | AISubtech-15.1.1 | Toxic / Unsafe / Inaccurate Content Generation | Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls. |
| HATE SPEECH | SOCIAL ENGINEERING | AITech-15.1 | Output Manipulation | AISubtech-15.1.1 | Toxic / Unsafe / Inaccurate Content Generation | Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls. |
| TOXIC CONTENT | SOCIAL ENGINEERING | AITech-15.1 | Output Manipulation | AISubtech-15.1.1 | Toxic / Unsafe / Inaccurate Content Generation | Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls. |
| VIOLENCE | MALICIOUS BEHAVIOR | AITech-15.1 | Output Manipulation | AISubtech-15.1.1 | Toxic / Unsafe / Inaccurate Content Generation | Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls. |
| SUSPICIOUS CODE EXECUTION | SUSPICIOUS CODE EXECUTION | AITech-9.1 | Model or Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components. |
| SOCIAL ENGINEERING | SOCIAL ENGINEERING | AITech-15.1 | Output Manipulation | AISubtech-15.1.1 | Toxic / Unsafe / Inaccurate Content Generation | Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls. |
| MALICIOUS BEHAVIOR | MALICIOUS BEHAVIOR | AITech-15.1 | Output Manipulation | AISubtech-15.1.1 | Toxic / Unsafe / Inaccurate Content Generation | Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls. |

## Scanner Categories

The scanner uses the following high-level categories to group threats:

| Category | Description |
|----------|-------------|
| PROMPT INJECTION | Attacks that manipulate prompts to alter LLM behavior |
| SUSPICIOUS CODE EXECUTION | Threats involving unauthorized code execution |
| SECURITY VIOLATION | General security violations including data exfiltration and unauthorized access |
| SOCIAL ENGINEERING | Threats involving manipulation or toxic content generation |
| MALICIOUS BEHAVIOR | Harmful or malicious activities |

## MCP Taxonomy Techniques

### Core Techniques Referenced

| Technique ID | Technique Name | Description |
|--------------|----------------|-------------|
| AITech-1.1 | Direct Prompt Injection | Attacks that directly manipulate prompts |
| AITech-1.4 | Injection Attacks (SQL, Command Execution, XSS) | Various injection attack vectors |
| AITech-8.2 | Data Exfiltration / Exposure | Unauthorized data access and exfiltration |
| AITech-9.1 | Model or Agentic System Manipulation | Manipulation of AI systems and agents |
| AITech-12.1 | Tool Exploitation | Exploitation of MCP tools |
| AITech-12.3 | Tool Injection / Shadowing | Tool-based attacks |
| AITech-15.1 | Output Manipulation | Manipulation of AI outputs |

## Accessing Taxonomy Information

### CLI Output

When using the CLI with `--detailed` flag, taxonomy information is displayed for each finding:

```bash
mcp-scanner --analyzers llm --detailed remote --server-url http://127.0.0.1:8000/mcp
```

Output includes:
```
Technique: AITech-1.1 - Direct Prompt Injection
Sub-Technique: AISubtech-1.1.1 - Instruction Manipulation (Direct Prompt Injection)
Description: Adversarial attack that attempts to alter or control...
```

### SDK Access

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
