"""
Threat mapping from scanner threat names to MCP Taxonomy.

This module provides mappings between different analyzers' threat names
and the standardized MCP Taxonomy threat classifications.
"""

from typing import Dict, Any


class ThreatMapping:
    """Mapping of threat names to MCP Taxonomy classifications."""
    
    # LLM Analyzer Threats
    LLM_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private data, intellectual property, and proprietary algorithms.",
        },
        "TOOL POISONING": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.3",
            "aisubtech_name": "Tool Poisoning",
            "description": "Altering the configuration, dependencies, or outputs of legitimate MCP tools to manipulate their behavior or responses, resulting in deceptive outputs, privilege escalation, or propagation of corrupted data across interconnected agentic or model-driven systems.",
        },
        "TOOL SHADOWING": {
            "scanner_category": "SECURITY VIOLATION",
            "aitech": "AITech-12.3",
            "aitech_name": "Tool Injection / Shadowing",
            "aisubtech": "AISubtech-12.3.1",
            "aisubtech_name": "Tool Shadowing",
            "description": "Disguising, substituting or duplicating legitimate tools within an MCP server or tool registry, enabling malicious tools with identical or similar identifiers to intercept or replace trusted tool calls, leading to unauthorized actions, data exfiltration, or redirection of legitimate operations.",
        },
        "SUSPICIOUS CODE EXECUTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components.",
        },
    }
    
    # YARA Analyzer Threats
    YARA_THREATS = {
        "PROMPT_INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input.",
        },
        "CODE_EXECUTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components.",
        },
        "COMMAND_INJECTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "aitech": "AITech-1.4",
            "aitech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "aisubtech": "AISubTech-1.4.1",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment.",
        },
        "CREDENTIAL_HARVESTING": {
            "scanner_category": "SECURITY VIOLATION",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private data, intellectual property, and proprietary algorithms.",
        },
        "SCRIPT_INJECTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "aitech": "AITech-1.4",
            "aitech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "aisubtech": "AISubTech-1.4.1",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment.",
        },
        "SQL_INJECTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "aitech": "AITech-1.4",
            "aitech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "aisubtech": "AISubTech-1.4.1",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment.",
        },
        "SYSTEM_MANIPULATION": {
            "scanner_category": "SECURITY VIOLATION",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "System Access",
            "description": "Manipulating or accessing underlying system resources without authorization, leading to unsolicited modification or deletion of files, registries, or permissions through model-driven or agent-executed commands system.",
        },
    }
    
    # AI Defense API Analyzer Threats
    AI_DEFENSE_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Adversarial attack that attempts to alter or control the output of a LLM or other related systems by providing instructions (via prompt) that override existing instructions and/or bypass model alignment or guardrails. A prompt injection technique is any transformation that preserves the intent of the input.",
        },
        "HARASSMENT": {
            "scanner_category": "SOCIAL ENGINEERING",
            "aitech": "AITech-15.1",
            "aitech_name": "Output Manipulation",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Toxic / Unsafe / Inaccurate Content Generation",
            "description": "Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls.",
        },
        "HATE SPEECH": {
            "scanner_category": "SOCIAL ENGINEERING",
            "aitech": "AITech-15.1",
            "aitech_name": "Output Manipulation",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Toxic / Unsafe / Inaccurate Content Generation",
            "description": "Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls.",
        },
        "TOXIC CONTENT": {
            "scanner_category": "SOCIAL ENGINEERING",
            "aitech": "AITech-15.1",
            "aitech_name": "Output Manipulation",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Toxic / Unsafe / Inaccurate Content Generation",
            "description": "Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls.",
        },
        "VIOLENCE": {
            "scanner_category": "MALICIOUS BEHAVIOR",
            "aitech": "AITech-15.1",
            "aitech_name": "Output Manipulation",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Toxic / Unsafe / Inaccurate Content Generation",
            "description": "Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls.",
        },
        "SUSPICIOUS CODE EXECUTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components.",
        },
        "SOCIAL ENGINEERING": {
            "scanner_category": "SOCIAL ENGINEERING",
            "aitech": "AITech-15.1",
            "aitech_name": "Output Manipulation",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Toxic / Unsafe / Inaccurate Content Generation",
            "description": "Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls.",
        },
        "MALICIOUS BEHAVIOR": {
            "scanner_category": "MALICIOUS BEHAVIOR",
            "aitech": "AITech-15.1",
            "aitech_name": "Output Manipulation",
            "aisubtech": "AISubtech-15.1.1",
            "aisubtech_name": "Toxic / Unsafe / Inaccurate Content Generation",
            "description": "Generating or facilitating toxic, unsafe, or inaccurate content - such as text, images, or audio - that bypasses or subverts model safety guardrails, resulting from manipulated prompts, unsafe tool use, or compromised content moderation controls.",
        },
    }
    
    @classmethod
    def get_threat_mapping(cls, analyzer: str, threat_name: str) -> Dict[str, Any]:
        """
        Get the MCP Taxonomy mapping for a given threat.
        
        Args:
            analyzer: The analyzer type ('llm', 'yara', or 'ai_defense')
            threat_name: The threat name from the analyzer
            
        Returns:
            Dictionary containing the threat mapping information
            
        Raises:
            ValueError: If analyzer or threat_name is not found
        """
        analyzer_map = {
            'llm': cls.LLM_THREATS,
            'yara': cls.YARA_THREATS,
            'ai_defense': cls.AI_DEFENSE_THREATS,
        }
        
        analyzer_lower = analyzer.lower()
        if analyzer_lower not in analyzer_map:
            raise ValueError(f"Unknown analyzer: {analyzer}")
        
        threats = analyzer_map[analyzer_lower]
        threat_upper = threat_name.upper()
        
        if threat_upper not in threats:
            raise ValueError(f"Unknown threat '{threat_name}' for analyzer '{analyzer}'")
        
        return threats[threat_upper]
    
    @classmethod
    def get_all_threats(cls) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        Get all threat mappings organized by analyzer.
        
        Returns:
            Dictionary with analyzer names as keys and their threat mappings as values
        """
        return {
            'llm': cls.LLM_THREATS,
            'yara': cls.YARA_THREATS,
            'ai_defense': cls.AI_DEFENSE_THREATS,
        }
