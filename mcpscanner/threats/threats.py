"""
Threat mapping from scanner threat names to MCP Taxonomy.

This module provides mappings between different analyzers' threat names
and the standardized MCP Taxonomy threat classifications.

The module is organized into two main sections:
1. THREAT DEFINITIONS: Complete threat definitions with taxonomy mappings and severity
2. SIMPLIFIED MAPPINGS & FUNCTIONS: Helper functions and lightweight mappings
"""

from typing import Dict, Any, Optional


# =============================================================================
# SECTION 1: THREAT DEFINITIONS
# =============================================================================

class ThreatMapping:
    """Mapping of threat names to MCP Taxonomy classifications with severity."""
    
    # LLM Analyzer Threats
    LLM_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override, replace, or modify the model's system instructions, operational directives, or behavioral guidelines through direct user input, causing the model to follow attacker-controlled instructions instead of its intended programming (e.g., \"Ignore previous instructions\").",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private or sensitive data, intellectual property, and proprietary algorithms through exploitation of agent tools, integrations, or capabilities, where the agent is manipulated to use legitimate tools for malicious data exfiltration purposes.",
        },
        "TOOL POISONING": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "Corrupting, modifying, or degrading the functionality, outputs, or behavior of tools used by agents through data poisoning, configuration tampering, or behavioral manipulation, causing the tool resulting in deceptive or malicious outputs, privilege escalation, or propagation of altered data.",
        },
        "TOOL SHADOWING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.5",
            "aisubtech_name": "Tool Shadowing",
            "description": "Disguising, substituting or duplicating legitimate tools within an agent or MCP server or tool registry, enabling malicious tools with identical or similar identifiers to intercept or replace trusted tool calls, leading to unauthorized actions, data exfiltration, or redirection of legitimate operations.",
        },
    }
    
    # YARA Analyzer Threats
    # Note: YARA rules use threat_type field which contains category-level values
    YARA_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override, replace, or modify the model's system instructions, operational directives, or behavioral guidelines through direct user input, causing the model to follow attacker-controlled instructions instead of its intended programming (e.g., \"Ignore previous instructions\").",
        },
        "CODE EXECUTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "LOW",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components.",
        },
        "INJECTION ATTACK": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts into MCP servers or tools that process model or user input, leading to data exposure, remote code execution, or compromise of the underlying system environment.",
        },
        "CREDENTIAL HARVESTING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, such as private or sensitive data, intellectual property, and proprietary algorithms through exploitation of agent tools, integrations, or capabilities, where the agent is manipulated to use legitimate tools for malicious data exfiltration purposes.",
        },
        "SYSTEM MANIPULATION": {
            "scanner_category": "SYSTEM MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Manipulating or accessing underlying system resources without authorization, leading to unsolicited modification or deletion of files, registries, or permissions through model-driven or agent-executed commands system.",
        },
    }
    
    # AI Defense API Analyzer Threats
    # Note: These are the actual classification values returned by Cisco AI Defense API
    AI_DEFENSE_THREATS = {
        "PROMPT_INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override, replace, or modify the model's system instructions, operational directives, or behavioral guidelines through direct user input, causing the model to follow attacker-controlled instructions instead of its intended programming (e.g., \"Ignore previous instructions\").",
        },
        "HARASSMENT": {
            "scanner_category": "SOCIAL ENGINEERING",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful / Misleading / Inaccurate Content",
            "aisubtech": "AISubtech-15.1.8",
            "aisubtech_name": "Safety Harms & Toxicity: Harassment",
            "description": "Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate harassment, intimidation, or targeted abuse.",
        },
        "HATE_SPEECH": {
            "scanner_category": "SOCIAL ENGINEERING",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful / Misleading / Inaccurate Content",
            "aisubtech": "AISubtech-15.1.9",
            "aisubtech_name": "Safety Harms & Toxicity: Hate Speech",
            "description": "Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate hateful, discriminatory, or demeaning expression targeting individuals or specific communities or characteristics of groups from protected classes such as race, ethnicity, religion, nationality, disability, gender, sexual orientation, or socioeconomic class.",
        },
        "PROFANITY": {
            "scanner_category": "SOCIAL ENGINEERING",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful / Misleading / Inaccurate Content",
            "aisubtech": "AISubtech-15.1.11",
            "aisubtech_name": "Safety Harms & Toxicity: Profanity",
            "description": "Prompts, content, or outputs from AI or agentic-systems that contain or promote profane, vulgar, or offensive language.",
        },
        "SEXUAL_CONTENT_AND_EXPLOITATION": {
            "scanner_category": "MALICIOUS BEHAVIOR",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful / Misleading / Inaccurate Content",
            "aisubtech": "AISubtech-15.1.14",
            "aisubtech_name": "Safety Harms & Toxicity: Sexual Content & Exploitation",
            "description": "Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate sexually explicit, exploitative, abusive, or harmful behaviors, often non-consensual and in violation of platform policies.",
        },
        "SOCIAL_DIVISION_AND_POLARIZATION": {
            "scanner_category": "SOCIAL ENGINEERING",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful / Misleading / Inaccurate Content",
            "aisubtech": "AISubtech-15.1.15",
            "aisubtech_name": "Safety Harms & Toxicity: Social Division & Polarization",
            "description": "Prompts, content, or outputs from AI or agentic-systems that encourage or reinforce social division, inequality, or polarization.",
        },
        "VIOLENCE_AND_PUBLIC_SAFETY_THREATS": {
            "scanner_category": "MALICIOUS BEHAVIOR",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful / Misleading / Inaccurate Content",
            "aisubtech": "AISubtech-15.1.17",
            "aisubtech_name": "Safety Harms & Toxicity: Violence & Public Safety Threat",
            "description": "Prompts, content, or outputs from AI or agentic-systems that enable, promote, or facilitate violence, physical harm, or threats to public safety.",
        },
        "CODE_DETECTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "LOW",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution targeted to large language models (LLMs), or agentic frameworks, systems (including MCP, A2A) often include integrated code interpreter or tool execution components.",
        },
        "SECURITY_VIOLATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Manipulating or accessing underlying system resources without authorization, leading to unsolicited modification or deletion of files, registries, or permissions through model-driven or agent-executed commands system.",
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
            Dictionary containing the threat mapping information including severity
            
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


# =============================================================================
# SECTION 2: SIMPLIFIED MAPPINGS & HELPER FUNCTIONS
# =============================================================================

def _create_simple_mapping(threats_dict):
    """Create simplified mapping with threat_category, threat_type, and severity."""
    return {
        name: {
            "threat_category": info["scanner_category"],
            "threat_type": name.lower().replace("_", " "),
            "severity": info.get("severity", "UNKNOWN"),
        }
        for name, info in threats_dict.items()
    }


# Simplified mappings for analyzers (includes severity, category, and type)
LLM_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.LLM_THREATS)
YARA_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.YARA_THREATS)
API_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.AI_DEFENSE_THREATS)
