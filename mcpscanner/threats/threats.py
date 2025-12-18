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
    
    # Behavioral Analyzer Threats
    # Note: These are description mismatch threats detected via semantic analysis
    BEHAVIORAL_THREATS = {
        # Injection & Interpretation Threats
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Malicious manipulation of tool metadata, descriptions, or decorators that mislead the LLM into invoking tools incorrectly or exposing confidential context; combined with injection of hidden or malicious instructions in MCP system/user prompts to alter model reasoning or bypass content restrictions.",
        },
        "INJECTION ATTACKS": {
            "scanner_category": "INJECTION ATTACKS",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Code carrying out injection attacks by embedding variables or unvalidated input into commands, templates, prompts, or expressions including shell or system commands built through string concatenation or variable substitution instead of fixed, parameterized calls.",
        },
        "TEMPLATE INJECTION": {
            "scanner_category": "TEMPLATE INJECTION",
            "severity": "MEDIUM",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.5",
            "aisubtech_name": "Template Injection (e.g., SSTI)",
            "description": "Injecting malicious template syntax into dynamically rendered prompts or server-side templates to execute arbitrary code. MCP decorator or response generator uses f-strings or template engines with unvalidated input.",
        },
        
        # Tool Integrity Threats
        "TOOL POISONING": {
            "scanner_category": "TOOL POISONING",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "Detect malicious code or logic inserted into registered MCP tools to mislead, manipulate outputs, or gain unauthorized access.",
        },
        "GOAL MANIPULATION": {
            "scanner_category": "GOAL MANIPULATION",
            "severity": "LOW",
            "aitech": "AITech-1.3",
            "aitech_name": "Goal Manipulation",
            "aisubtech": "AISubtech-1.3.2",
            "aisubtech_name": "Goal Manipulation (Tools, Prompts, Resources)",
            "description": "Detect tampering with the intended purpose of a tool, prompt, or resource to steer the LLM toward attacker-defined objectives. Includes code with injection points in tool chaining, prompt composition, or control-flow templates.",
        },
        
        # Data Exfiltration & Access Threats
        "DATA EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Extracting or leaking sensitive information (e.g., API keys, configs, proprietary code) from the MCP environment via code behavior or LLM responses.",
        },
        "UNAUTHORIZED OR UNSOLICITED NETWORK ACCESS": {
            "scanner_category": "UNAUTHORIZED OR UNSOLICITED NETWORK ACCESS",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.3",
            "aisubtech_name": "Unauthorized or Unsolicited Network Access",
            "description": "Implementation that manipulates MCP tools or resources to send unauthorized requests to internal or external endpoints, potentially exposing sensitive infrastructure (SSRF).",
        },
        "UNAUTHORIZED OR UNSOLICITED SYSTEM ACCESS": {
            "scanner_category": "UNAUTHORIZED OR UNSOLICITED SYSTEM ACCESS",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Code includes file-system, process, or environment-level operations (os, pathlib, shutil, open, os.environ) that are not scoped, validated, or restricted, enabling direct access to system state.",
        },
        "ARBITRARY RESOURCE READ/WRITE": {
            "scanner_category": "ARBITRARY RESOURCE READ/WRITE",
            "severity": "MEDIUM",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.3",
            "aisubtech_name": "Unsafe System / Browser / File Exec",
            "description": "Detect unauthorized reading from or writing to arbitrary resources such as files, URLs, APIs, databases, or local storage via tool or resource misuse. Includes path traversal attacks.",
        },
        
        # Execution & Payload Threats
        "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION": {
            "scanner_category": "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Code carrying out arbitrary or unintended code execution through insecure tool definitions, unsafe evaluation constructs (eval, exec, compile, deserialization, or dynamic imports), or embedded logic that enables RCE-like behavior without explicit developer intent.",
        },
        "BACKDOOR": {
            "scanner_category": "BACKDOOR",
            "severity": "HIGH",
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.2",
            "aisubtech_name": "Backdoors and Trojans",
            "description": "Hidden malicious logic embedded in code or decorators, allowing persistent unauthorized access or control over MCP behavior.",
        },
        "DEFENSE EVASION": {
            "scanner_category": "DEFENSE EVASION",
            "severity": "LOW",
            "aitech": "AITech-11.1",
            "aitech_name": "Environment-Aware Evasion",
            "aisubtech": "AISubtech-11.1.2",
            "aisubtech_name": "Tool-Scoped Evasion",
            "description": "Techniques to bypass sandbox or isolation boundaries to execute or modify code outside the restricted MCP environment. Tool imports ctypes or uses os.execv to spawn external processes; evidence of system-level interaction beyond allowed scope.",
        },
        "RESOURCE EXHAUSTION": {
            "scanner_category": "RESOURCE EXHAUSTION",
            "severity": "MEDIUM",
            "aitech": "AITech-13.1",
            "aitech_name": "Disruption of Availability",
            "aisubtech": "AISubtech-13.1.1",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Overloading the MCP server (via repeated tool invocations or large payloads) to degrade performance or cause denial of service. Tool repeatedly processes large files or calls itself recursively without rate limits or break conditions.",
        },
        
        # General Behavioral & Metadata Threats
        "GENERAL DESCRIPTION-CODE MISMATCH": {
            "scanner_category": "GENERAL DESCRIPTION-CODE MISMATCH",
            "severity": "INFO",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "General behavioral mismatch category for non-security issues like missing docstrings with safe code implementation. Only receives INFO severity when there's no security implication - purely documentation quality issues.",
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
            'behavioral': cls.BEHAVIORAL_THREATS,
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
BEHAVIORAL_THREAT_MAPPING = _create_simple_mapping(ThreatMapping.BEHAVIORAL_THREATS)
