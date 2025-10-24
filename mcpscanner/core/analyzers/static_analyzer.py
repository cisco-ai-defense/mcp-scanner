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

"""Static File Analyzer module for MCP Scanner SDK.

This module contains the static analyzer for scanning pre-generated MCP JSON files
without connecting to a live server. Useful for CI/CD pipelines and offline scanning.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .base import BaseAnalyzer, SecurityFinding
from ..models import AnalyzerEnum


class StaticAnalyzer:
    """Analyzer for scanning pre-generated MCP JSON files.
    
    This analyzer reads static JSON files containing MCP tools, prompts, or resources
    and coordinates scanning using the provided sub-analyzers (YARA, LLM, API).
    
    This is NOT a security analyzer itself - it's a coordinator that:
    1. Reads static JSON files
    2. Parses MCP protocol structures
    3. Delegates actual security analysis to other analyzers
    
    Example:
        >>> from mcpscanner import Config
        >>> from mcpscanner.core.analyzers import StaticAnalyzer, YaraAnalyzer
        >>> 
        >>> yara = YaraAnalyzer()
        >>> static = StaticAnalyzer(analyzers=[yara])
        >>> 
        >>> results = await static.scan_tools_file("tools-list.json")
        >>> for result in results:
        ...     print(f"Tool: {result.tool_name}, Safe: {result.is_safe}")
    """

    def __init__(
        self, 
        analyzers: Optional[List[BaseAnalyzer]] = None,
        config: Optional[Any] = None
    ):
        """Initialize a new StaticAnalyzer instance.
        
        Args:
            analyzers: List of analyzer instances to use for scanning.
            config: Optional configuration object (for future use).
        """
        self.analyzers = analyzers or []
        self.config = config

    def _load_json_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Load and parse a JSON file.
        
        Args:
            file_path: Path to the JSON file.
            
        Returns:
            Dict[str, Any]: Parsed JSON content.
            
        Raises:
            FileNotFoundError: If the file doesn't exist.
            json.JSONDecodeError: If the file contains invalid JSON.
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not path.is_file():
            raise ValueError(f"Not a file: {file_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                raise json.JSONDecodeError(
                    f"Invalid JSON in {file_path}: {e.msg}",
                    e.doc,
                    e.pos
                )

    async def _analyze_content(
        self, 
        content: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Run all configured analyzers on the content.
        
        Args:
            content: Content to analyze.
            context: Additional context for analysis.
            
        Returns:
            List[SecurityFinding]: Combined findings from all analyzers.
        """
        all_findings = []
        
        for analyzer in self.analyzers:
            try:
                findings = await analyzer.analyze(content, context)
                all_findings.extend(findings)
            except Exception as e:
                # Log error but continue with other analyzers
                print(f"Warning: {analyzer.name} failed: {e}")
        
        return all_findings

    async def scan_tools_file(
        self, 
        file_path: Union[str, Path]
    ) -> List[Dict[str, Any]]:
        """Scan a JSON file containing MCP tools/list output.
        
        Expected JSON format:
        {
          "tools": [
            {
              "name": "tool_name",
              "description": "Tool description",
              "inputSchema": {...}
            }
          ]
        }
        
        Args:
            file_path: Path to the tools JSON file.
            
        Returns:
            List[Dict]: List of scan results with structure:
                {
                    "tool_name": str,
                    "tool_description": str,
                    "is_safe": bool,
                    "findings": List[SecurityFinding],
                    "status": str
                }
                
        Raises:
            FileNotFoundError: If file doesn't exist.
            json.JSONDecodeError: If file contains invalid JSON.
            ValueError: If JSON structure is invalid.
        """
        data = self._load_json_file(file_path)
        
        if "tools" not in data:
            raise ValueError(f"Invalid tools file: missing 'tools' key in {file_path}")
        
        if not isinstance(data["tools"], list):
            raise ValueError(f"Invalid tools file: 'tools' must be an array in {file_path}")
        
        results = []
        
        for tool_data in data["tools"]:
            tool_name = tool_data.get("name", "unknown")
            tool_description = tool_data.get("description", "")
            
            all_findings = []
            
            # Analyze description
            if tool_description:
                desc_context = {
                    "tool_name": tool_name,
                    "content_type": "description"
                }
                desc_findings = await self._analyze_content(
                    tool_description, 
                    desc_context
                )
                all_findings.extend(desc_findings)
            
            # Analyze parameters (if present)
            if "inputSchema" in tool_data:
                # Remove description to avoid duplicate analysis
                params_data = {k: v for k, v in tool_data.items() if k != "description"}
                params_json = json.dumps(params_data)
                
                params_context = {
                    "tool_name": tool_name,
                    "content_type": "parameters"
                }
                params_findings = await self._analyze_content(
                    params_json,
                    params_context
                )
                all_findings.extend(params_findings)
            
            result = {
                "tool_name": tool_name,
                "tool_description": tool_description,
                "is_safe": len(all_findings) == 0,
                "findings": all_findings,
                "status": "completed",
                "analyzers": [a.name for a in self.analyzers]
            }
            
            results.append(result)
        
        return results

    async def scan_prompts_file(
        self,
        file_path: Union[str, Path]
    ) -> List[Dict[str, Any]]:
        """Scan a JSON file containing MCP prompts/list output.
        
        Expected JSON format:
        {
          "prompts": [
            {
              "name": "prompt_name",
              "description": "Prompt description",
              "arguments": [...]
            }
          ]
        }
        
        Args:
            file_path: Path to the prompts JSON file.
            
        Returns:
            List[Dict]: List of scan results.
            
        Raises:
            FileNotFoundError: If file doesn't exist.
            json.JSONDecodeError: If file contains invalid JSON.
            ValueError: If JSON structure is invalid.
        """
        data = self._load_json_file(file_path)
        
        if "prompts" not in data:
            raise ValueError(f"Invalid prompts file: missing 'prompts' key in {file_path}")
        
        if not isinstance(data["prompts"], list):
            raise ValueError(f"Invalid prompts file: 'prompts' must be an array in {file_path}")
        
        results = []
        
        for prompt_data in data["prompts"]:
            prompt_name = prompt_data.get("name", "unknown")
            prompt_description = prompt_data.get("description", "")
            
            # Analyze prompt content
            analysis_content = f"Prompt Name: {prompt_name}\n"
            analysis_content += f"Description: {prompt_description}\n"
            
            if "arguments" in prompt_data:
                analysis_content += f"Arguments: {json.dumps(prompt_data['arguments'], indent=2)}\n"
            
            context = {
                "prompt_name": prompt_name,
                "content_type": "prompt"
            }
            
            findings = await self._analyze_content(analysis_content, context)
            
            result = {
                "prompt_name": prompt_name,
                "prompt_description": prompt_description,
                "is_safe": len(findings) == 0,
                "findings": findings,
                "status": "completed",
                "analyzers": [a.name for a in self.analyzers]
            }
            
            results.append(result)
        
        return results

    async def scan_resources_file(
        self,
        file_path: Union[str, Path],
        allowed_mime_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Scan a JSON file containing MCP resources/list output.
        
        Expected JSON format:
        {
          "resources": [
            {
              "uri": "file:///path/to/resource",
              "name": "Resource name",
              "description": "Resource description",
              "mimeType": "text/plain"
            }
          ]
        }
        
        Args:
            file_path: Path to the resources JSON file.
            allowed_mime_types: Optional list of MIME types to scan. Others are skipped.
            
        Returns:
            List[Dict]: List of scan results.
            
        Raises:
            FileNotFoundError: If file doesn't exist.
            json.JSONDecodeError: If file contains invalid JSON.
            ValueError: If JSON structure is invalid.
        """
        data = self._load_json_file(file_path)
        
        if "resources" not in data:
            raise ValueError(f"Invalid resources file: missing 'resources' key in {file_path}")
        
        if not isinstance(data["resources"], list):
            raise ValueError(f"Invalid resources file: 'resources' must be an array in {file_path}")
        
        results = []
        
        for resource_data in data["resources"]:
            resource_uri = resource_data.get("uri", "unknown")
            resource_name = resource_data.get("name", "unknown")
            resource_description = resource_data.get("description", "")
            resource_mime = resource_data.get("mimeType", "application/octet-stream")
            
            # Check MIME type filter
            if allowed_mime_types and resource_mime not in allowed_mime_types:
                result = {
                    "resource_uri": resource_uri,
                    "resource_name": resource_name,
                    "resource_description": resource_description,
                    "resource_mime_type": resource_mime,
                    "is_safe": True,
                    "findings": [],
                    "status": "skipped",
                    "analyzers": []
                }
                results.append(result)
                continue
            
            # Analyze resource metadata
            analysis_content = f"Resource URI: {resource_uri}\n"
            analysis_content += f"Name: {resource_name}\n"
            analysis_content += f"Description: {resource_description}\n"
            analysis_content += f"MIME Type: {resource_mime}\n"
            
            context = {
                "resource_uri": resource_uri,
                "resource_name": resource_name,
                "content_type": "resource"
            }
            
            findings = await self._analyze_content(analysis_content, context)
            
            result = {
                "resource_uri": resource_uri,
                "resource_name": resource_name,
                "resource_description": resource_description,
                "resource_mime_type": resource_mime,
                "is_safe": len(findings) == 0,
                "findings": findings,
                "status": "completed",
                "analyzers": [a.name for a in self.analyzers]
            }
            
            results.append(result)
        
        return results

