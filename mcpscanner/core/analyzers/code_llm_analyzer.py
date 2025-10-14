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

"""Code LLM Analyzer for MCP Server Functions.

This analyzer scans MCP server code from GitHub repositories or local files
using LLM-based analysis to detect security vulnerabilities including data exfiltration and command injection.
"""

import asyncio
import json
import logging
import re
import secrets
import shutil
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from git import Repo
    GITPYTHON_AVAILABLE = True
except ImportError:
    GITPYTHON_AVAILABLE = False

try:
    from litellm import acompletion
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False

from ...config.config import Config
from ...config.constants import MCPScannerConstants
from ...utils.code_flow_tracker import track_code_flow, get_flow_summary, MultiFileCodeFlowTracker
from .base import BaseAnalyzer, SecurityFinding

logger = logging.getLogger(__name__)


class SupportedLanguage(str, Enum):
    """Supported programming languages for MCP server scanning."""

    PYTHON = "python"
    TYPESCRIPT = "typescript"
    KOTLIN = "kotlin"
    SWIFT = "swift"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities detected in MCP server functions."""

    REMOTE_CODE_EXECUTION = "remote_code_execution"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    SSRF = "server_side_request_forgery"
    SSTI = "server_side_template_injection"
    ARBITRARY_FILE_READ = "arbitrary_file_read"
    ARBITRARY_FILE_WRITE = "arbitrary_file_write"
    PATH_TRAVERSAL = "path_traversal"


@dataclass
class MCPFunction:
    """Represents an extracted MCP server function."""

    function_type: str  # "tool", "resource", or "prompt"
    function_name: str
    file_path: str
    line_number: int
    language: SupportedLanguage
    code_snippet: str
    decorator_or_registration: str


class CodeLLMAnalyzer(BaseAnalyzer):
    """Analyzer for scanning MCP server functions using LLM-based code analysis."""

    def __init__(self, config: Config, github_token: Optional[str] = None):
        """Initialize the Code LLM analyzer.
        
        Args:
            config: Configuration object with LLM settings
            github_token: Optional GitHub personal access token (not used for git clone).
        """
        super().__init__("CodeLLMAnalyzer")
        self.description = "Scans MCP server code for security vulnerabilities using LLM-based analysis"

        # Initialize LLM configuration
        if not LITELLM_AVAILABLE:
            logger.warning("LiteLLM library not installed. Install with: pip install litellm")
            self.llm_enabled = False
        elif not hasattr(config, "llm_provider_api_key") or not config.llm_provider_api_key:
            logger.warning("LLM provider API key not configured. LLM analysis will be disabled.")
            self.llm_enabled = False
        else:
            self.llm_enabled = True
            self._config = config
            self._api_key = config.llm_provider_api_key
            self._base_url = config.llm_base_url
            self._api_version = config.llm_api_version
            self._model = config.llm_model
            self._max_tokens = config.llm_max_tokens
            self._temperature = config.llm_temperature
            self._rate_limit_delay = config.llm_rate_limit_delay
            self._max_retries = config.llm_max_retries

        # Language-specific MCP patterns
        # Match both FastMCP style (@mcp.tool, @jira_mcp.tool) and standard MCP SDK style (@server.call_tool)
        self.mcp_patterns = {
            SupportedLanguage.PYTHON: {
                # Matches: @mcp.tool(), @jira_mcp.tool(), @app.tool(), @server.call_tool(), @server.list_tools()
                # Pattern: @<any_word>.tool() or @<any_word>.call_tool() etc.
                "tool": r"@[\w_]+\.(tool|call_tool|list_tools)\(",
                # Matches: @mcp.resource("uri"), @jira_mcp.resource(), @server.list_resources()
                "resource": r"@[\w_]+\.(resource|list_resources|read_resource)\(",
                # Matches: @mcp.prompt(), @jira_mcp.prompt(), @server.list_prompts(), @server.get_prompt()
                "prompt": r"@[\w_]+\.(prompt|list_prompts|get_prompt)\(",
            },
            SupportedLanguage.TYPESCRIPT: {
                "tool": r"server\.registerTool\(",
                "resource": r"server\.registerResource\(",
                "prompt": r"server\.registerPrompt\(",
            },
            SupportedLanguage.KOTLIN: {
                "tool": r"server\.addTool",
                "resource": r"server\.addResource",
                "prompt": r"server\.addPrompt",
            },
            SupportedLanguage.SWIFT: {
                "tool": r"await\s+server\.withMethodHandler\(CallTool\.self\)",
                "resource": r"await\s+server\.withMethodHandler\(ListResources\.self\)",
                "prompt": r"await\s+server\.withMethodHandler\(GetPrompt\.self\)",
            },
        }

        # File extensions for each language
        self.language_extensions = {
            SupportedLanguage.PYTHON: [".py"],
            SupportedLanguage.TYPESCRIPT: [".ts", ".js"],
            SupportedLanguage.KOTLIN: [".kt", ".kts"],
            SupportedLanguage.SWIFT: [".swift"],
        }

    def _load_prompt(self, prompt_file_name: str) -> str:
        """Load a prompt from a markdown file.

        Args:
            prompt_file_name: The name of the prompt file.

        Returns:
            str: The prompt content.

        Raises:
            FileNotFoundError: If the prompt file cannot be found.
            IOError: If the prompt file cannot be read.
        """
        try:
            prompt_file = MCPScannerConstants.get_prompts_path() / prompt_file_name

            if not prompt_file.is_file():
                raise FileNotFoundError(f"Prompt file not found: {prompt_file_name}")

            return prompt_file.read_text(encoding="utf-8")

        except FileNotFoundError:
            logger.error(f"Prompt file not found: {prompt_file_name}")
            raise
        except Exception as e:
            logger.error(f"Failed to load prompt {prompt_file_name}: {e}")
            raise IOError(f"Could not load prompt {prompt_file_name}: {e}")

    def _parse_github_url(self, repo_url: str) -> Optional[tuple]:
        """Parse GitHub URL to extract owner and repository name.

        Args:
            repo_url: GitHub repository URL

        Returns:
            Tuple of (owner, repo_name) or None if invalid
        """
        try:
            parsed = urlparse(repo_url)
            if parsed.netloc not in ["github.com", "www.github.com"]:
                return None
            
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) < 2:
                return None
            
            owner = path_parts[0]
            repo_name = path_parts[1].replace(".git", "")
            return (owner, repo_name)
        except Exception as e:
            logger.error(f"Failed to parse GitHub URL {repo_url}: {e}")
            return None

    def _clone_repository(self, repo_url: str, target_dir: str) -> bool:
        """Clone a GitHub repository using GitPython.

        Args:
            repo_url: GitHub repository URL
            target_dir: Target directory to clone into

        Returns:
            True if successful, False otherwise
        """
        if not GITPYTHON_AVAILABLE:
            logger.error("GitPython library not installed. Install with: pip install gitpython")
            return False
            
        try:
            logger.info(f"Cloning repository: {repo_url} to {target_dir}")
            # Clone with depth=1 for faster cloning (shallow clone)
            Repo.clone_from(repo_url, target_dir, depth=1)
            logger.info(f"Repository cloned successfully to {target_dir}")
            return True
                
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            return False

    def _detect_language_from_filename(self, filename: str) -> Optional[SupportedLanguage]:
        """Detect the programming language from a filename.

        Args:
            filename: Name of the file

        Returns:
            Detected language or None
        """
        extension = "." + filename.split(".")[-1] if "." in filename else ""
        extension = extension.lower()
        
        for language, extensions in self.language_extensions.items():
            if extension in extensions:
                return language
        return None

    def _extract_function_name(
        self, code: str, pattern: str, language: SupportedLanguage
    ) -> Optional[str]:
        """Extract function name from code based on language-specific patterns.

        Args:
            code: Source code
            pattern: Pattern that matched
            language: Programming language

        Returns:
            Function name or None
        """
        try:
            if language == SupportedLanguage.PYTHON:
                # Look for def function_name after decorator
                match = re.search(r"def\s+(\w+)\s*\(", code)
                if match:
                    return match.group(1)
            elif language == SupportedLanguage.TYPESCRIPT:
                # Look for function name in registration
                match = re.search(r'["\'](\w+)["\']', code)
                if match:
                    return match.group(1)
            elif language == SupportedLanguage.KOTLIN:
                # Look for function name in Kotlin
                match = re.search(r"fun\s+(\w+)\s*\(", code)
                if match:
                    return match.group(1)
            elif language == SupportedLanguage.SWIFT:
                # Look for function name in Swift
                match = re.search(r"func\s+(\w+)\s*\(", code)
                if match:
                    return match.group(1)
        except Exception as e:
            logger.debug(f"Failed to extract function name: {e}")
        return None

    def _extract_full_function_code(self, lines: List[str], decorator_line: int) -> tuple:
        """Extract the complete function code starting from a decorator.
        
        Extracts from the decorator line (@server.call_tool, @mcp.tool, etc.)
        through the entire function body until the next function or class.
        
        Args:
            lines: All lines of the file
            decorator_line: Line number where decorator appears (0-indexed)
            
        Returns:
            Tuple of (function_code, end_line_number)
        """
        # Start from the decorator line
        start_line = decorator_line
        
        # Go backwards to find any other decorators above this line
        for i in range(decorator_line - 1, max(0, decorator_line - 10), -1):
            line = lines[i].strip()
            if line.startswith('@') or not line:
                start_line = i
            else:
                break
        
        # Find the function definition line (starts with 'def' or 'async def')
        func_def_line = decorator_line
        for i in range(decorator_line, min(decorator_line + 10, len(lines))):
            if 'def ' in lines[i]:
                func_def_line = i
                break
        
        # Get the indentation level of the function definition
        func_line = lines[func_def_line]
        func_indent = len(func_line) - len(func_line.lstrip())
        
        # Extract all lines from start_line until we hit another function/class at same or less indentation
        func_lines = []
        for i in range(start_line, len(lines)):
            line = lines[i]
            
            # Always include empty lines within the function
            if not line.strip():
                func_lines.append(line)
                continue
            
            # Get current line indentation
            current_indent = len(line) - len(line.lstrip())
            
            # If we're past the function definition and hit same/less indentation, check if we should stop
            if i > func_def_line and current_indent <= func_indent and line.strip():
                # Stop if we hit another decorator, function, or class at same/less indentation
                if line.strip().startswith('@') or line.strip().startswith('def ') or line.strip().startswith('async def') or line.strip().startswith('class '):
                    break
            
            func_lines.append(line)
        
        return "\n".join(func_lines), start_line + len(func_lines)

    def _extract_mcp_functions(
        self, file_content: str, file_path: str, language: SupportedLanguage
    ) -> List[MCPFunction]:
        """Extract MCP server functions from source code content.

        Args:
            file_content: Source code content
            file_path: Path to the file (for reference)
            language: Programming language

        Returns:
            List of extracted MCP functions
        """
        functions = []
        try:
            lines = file_content.split("\n")
            patterns = self.mcp_patterns.get(language, {})
            
            for func_type, pattern in patterns.items():
                for match in re.finditer(pattern, file_content, re.MULTILINE):
                    # Find line number
                    line_num = file_content[: match.start()].count("\n") + 1

                    # Extract FULL function code (not just snippet)
                    full_code, end_line = self._extract_full_function_code(lines, line_num - 1)

                    # Extract function name
                    func_name = self._extract_function_name(
                        full_code, pattern, language
                    )
                    if not func_name:
                        func_name = f"unknown_{func_type}_{line_num}"

                    functions.append(
                        MCPFunction(
                            function_type=func_type,
                            function_name=func_name,
                            file_path=file_path,
                            line_number=line_num,
                            language=language,
                            code_snippet=full_code,  # Now contains FULL function code
                            decorator_or_registration=match.group(0),
                        )
                    )

        except Exception as e:
            logger.error(f"Error extracting functions from {file_path}: {e}")

        return functions

    def _load_vulnerability_analysis_prompt(self) -> str:
        """Load the code vulnerability analysis prompt from file.
        
        Returns:
            The prompt template content
            
        Raises:
            FileNotFoundError: If the prompt file cannot be found
            IOError: If the prompt file cannot be read
        """
        prompt_file = Path(__file__).parent.parent.parent / "data" / "prompts" / "code_vulnerability_analysis_prompt.md"
        with open(prompt_file, 'r', encoding='utf-8') as f:
            return f.read()

    async def _analyze_function_with_llm(
        self, mcp_function: MCPFunction, flow_tracker: Optional[MultiFileCodeFlowTracker] = None
    ) -> List[SecurityFinding]:
        """Analyze an MCP function for security vulnerabilities using LLM.

        Args:
            mcp_function: MCP function to analyze
            flow_tracker: Optional multi-file flow tracker with pre-computed flows

        Returns:
            List of security findings
        """
        if not self.llm_enabled:
            return []

        findings = []
        
        try:
            # Load the vulnerability analysis prompt template
            prompt_template = self._load_vulnerability_analysis_prompt()
            
            # Perform data flow analysis for Python code
            flow_analysis = ""
            if mcp_function.language == SupportedLanguage.PYTHON:
                try:
                    # Use multi-file flow tracker if available, otherwise single-file
                    if flow_tracker:
                        # Get flow report for this specific file
                        file_flow_report = flow_tracker.get_file_report(mcp_function.file_path)
                        if file_flow_report and file_flow_report.get('total_parameters', 0) > 0:
                            flow_summary = get_flow_summary(file_flow_report)
                            flow_analysis = f"\n\n**Data Flow Analysis (Multi-File Context)**:\n{flow_summary}\n"
                            logger.info(f"Using multi-file flow analysis for {mcp_function.function_name}: {file_flow_report.get('total_parameters', 0)} parameters tracked")
                    else:
                        # Fallback to single-file analysis
                        flow_report = track_code_flow(mcp_function.code_snippet, mcp_function.file_path)
                        if flow_report and flow_report.get('total_parameters', 0) > 0:
                            flow_summary = get_flow_summary(flow_report)
                            flow_analysis = f"\n\n**Data Flow Analysis**:\n{flow_summary}\n"
                            logger.info(f"Generated flow analysis for {mcp_function.function_name}: {flow_report.get('total_parameters', 0)} parameters tracked")
                except Exception as e:
                    logger.warning(f"Could not perform flow analysis for {mcp_function.function_name}: {e}")
            
            # Create analysis prompt with function details
            random_id = secrets.token_hex(16)
            start_tag = f"<!---UNTRUSTED_CODE_START_{random_id}--->"
            end_tag = f"<!---UNTRUSTED_CODE_END_{random_id}--->"

            function_details = f"""
**Function Type**: {mcp_function.function_type}
**Function Name**: {mcp_function.function_name}
**Programming Language**: {mcp_function.language.value}
**File Path**: {mcp_function.file_path}
**Line Number**: {mcp_function.line_number}
{flow_analysis}
{start_tag}
```{mcp_function.language.value}
{mcp_function.code_snippet}
```
{end_tag}
"""

            analysis_prompt = prompt_template + "\n\n" + function_details

            # Call LLM
            response = await acompletion(
                model=self._model,
                messages=[{"role": "user", "content": analysis_prompt}],
                api_key=self._api_key,
                base_url=self._base_url,
                api_version=self._api_version,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )

            # Parse response
            response_text = response.choices[0].message.content
            
            # Extract JSON array from response
            # Try to find JSON array first
            json_array_match = re.search(r'\[.*\]', response_text, re.DOTALL)
            if json_array_match:
                vulnerabilities = json.loads(json_array_match.group())
                
                # Process each vulnerability finding
                for vuln in vulnerabilities:
                    finding = SecurityFinding(
                        severity=vuln.get("severity", "medium").lower(),
                        summary=vuln.get("summary", f"Security issue in {mcp_function.function_type} '{mcp_function.function_name}'"),
                        threat_category=vuln.get("threat_category", "Code Vulnerability"),
                        details=vuln.get("details", "No details provided"),
                        analyzer="CodeLLMAnalyzer",
                    )
                    findings.append(finding)
            else:
                logger.warning(f"No JSON array found in LLM response for {mcp_function.function_name}")

            # Rate limiting
            if self._rate_limit_delay > 0:
                await asyncio.sleep(self._rate_limit_delay)

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON response for {mcp_function.function_name}: {e}")
        except Exception as e:
            logger.error(f"Error analyzing function {mcp_function.function_name} with LLM: {e}")

        return findings

    async def analyze(
        self,
        content: str,
        context: Optional[Dict] = None,
        http_headers: Optional[Dict] = None,
    ) -> List[SecurityFinding]:
        """Analyze a GitHub repository for MCP server vulnerabilities using PyGithub SDK and LLM.

        Args:
            content: GitHub repository URL
            context: Optional context (not used)
            http_headers: Optional HTTP headers (not used)

        Returns:
            List of security findings
        """
        repo_url = content.strip()
        findings = []

        # Parse GitHub URL
        parsed_repo = self._parse_github_url(repo_url)
        if not parsed_repo:
            logger.error(f"Invalid GitHub repository URL: {repo_url}")
            return [
                SecurityFinding(
                    severity="info",
                    summary="Invalid GitHub URL",
                    threat_category="Configuration",
                    details="The provided URL is not a valid GitHub repository URL",
                    analyzer="CodeLLMAnalyzer",
                )
            ]

        owner, repo_name = parsed_repo
        
        # Create temporary directory for cloning
        temp_dir = tempfile.mkdtemp(prefix="mcp_scanner_github_")
        
        try:
            # Clone the repository
            if not self._clone_repository(repo_url, temp_dir):
                return [
                    SecurityFinding(
                        severity="info",
                        summary="Failed to clone repository",
                        threat_category="Configuration",
                        details=f"Could not clone repository {repo_url}. It may be private or not exist.",
                        analyzer="CodeLLMAnalyzer",
                    )
                ]
            
            # Scan all supported files in the cloned repository
            all_functions = []
            files_scanned = 0
            
            logger.info("Starting to scan repository contents...")
            repo_path = Path(temp_dir)
            
            # Initialize multi-file flow tracker for Python files
            flow_tracker = MultiFileCodeFlowTracker()
            python_files = []
            
            # Recursively scan Python files only
            language = SupportedLanguage.PYTHON
            extensions = self.language_extensions[language]
            
            for ext in extensions:
                for file_path in repo_path.rglob(f"*{ext}"):
                    # Skip common non-source directories
                    if any(skip in file_path.parts for skip in [
                        "node_modules", ".git", "venv", ".venv", "build", "dist", "__pycache__", ".next", "site-packages"
                    ]):
                        continue
                    
                    try:
                        logger.debug(f"Scanning file: {file_path.relative_to(repo_path)} (language: {language.value})")
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            file_data = f.read()
                        
                        files_scanned += 1
                        python_files.append(str(file_path))
                        
                        # Add to flow tracker
                        flow_tracker.add_file(str(file_path), source_code=file_data)
                        
                        # Extract MCP functions
                        functions = self._extract_mcp_functions(
                            file_data, str(file_path.relative_to(repo_path)), language
                        )
                        if functions:
                            logger.info(f"Found {len(functions)} MCP functions in {file_path.relative_to(repo_path)}")
                        all_functions.extend(functions)
                        
                    except Exception as e:
                        logger.warning(f"Error processing file {file_path}: {e}")
                        continue

            logger.info(f"Scan complete: Scanned {files_scanned} files, found {len(all_functions)} MCP functions")
            
            # Perform multi-file flow analysis
            flow_report = None
            if python_files:
                try:
                    logger.info(f"Performing multi-file flow analysis on {len(python_files)} Python files...")
                    flow_report = flow_tracker.analyze()
                    logger.info(
                        f"Flow analysis complete: {flow_report['total_parameters']} parameters, "
                        f"{flow_report['total_flow_events']} flow events across {flow_report['files_with_flows']} files"
                    )
                except Exception as e:
                    logger.warning(f"Multi-file flow analysis failed: {e}")

            # Check if any Python files were found
            if files_scanned == 0:
                return [
                    SecurityFinding(
                        severity="info",
                        summary="No Python files found in repository",
                        threat_category="Configuration",
                        details="This analyzer only supports Python code. No .py files were found in the repository.",
                        analyzer="CodeLLMAnalyzer",
                    )
                ]

            # Check if any MCP functions were found
            if len(all_functions) == 0:
                return [
                    SecurityFinding(
                        severity="info",
                        summary="No MCP functions found",
                        threat_category="Configuration",
                        details=f"Scanned {files_scanned} Python files but found no MCP server functions. "
                               f"This analyzer looks for @mcp.tool(), @mcp.prompt(), @mcp.resource() decorators.",
                        analyzer="CodeLLMAnalyzer",
                    )
                ]

            # Analyze each function with LLM for vulnerabilities (with multi-file flow context)
            for mcp_func in all_functions:
                func_findings = await self._analyze_function_with_llm(mcp_func, flow_tracker=flow_tracker)
                findings.extend(func_findings)

            # Add summary finding
            if all_functions:
                summary_details = {
                    "total_functions": len(all_functions),
                    "functions_by_type": {},
                    "functions_by_language": {},
                    "vulnerabilities_found": len(findings),
                }

                for func in all_functions:
                    summary_details["functions_by_type"][func.function_type] = (
                        summary_details["functions_by_type"].get(func.function_type, 0) + 1
                    )
                    summary_details["functions_by_language"][func.language.value] = (
                        summary_details["functions_by_language"].get(func.language.value, 0) + 1
                    )

                summary_str = f"Repository scan complete: {len(all_functions)} MCP functions analyzed\n"
                summary_str += f"Functions by type: {summary_details['functions_by_type']}\n"
                summary_str += f"Functions by language: {summary_details['functions_by_language']}\n"
                summary_str += f"Vulnerabilities found: {summary_details['vulnerabilities_found']}"
                
                findings.insert(
                    0,
                    SecurityFinding(
                        severity="info",
                        summary=f"Repository scan complete: {len(all_functions)} MCP functions analyzed",
                        threat_category="Summary",
                        details=summary_str,
                        analyzer="CodeLLMAnalyzer",
                    ),
                )

        except UnknownObjectException:
            logger.error(f"Repository not found: {owner}/{repo_name}")
            return [
                SecurityFinding(
                    severity="info",
                    summary="Repository not found",
                    threat_category="Configuration",
                    details=f"Repository {owner}/{repo_name} not found or is private",
                    analyzer="CodeLLMAnalyzer",
                )
            ]
        except GithubException as e:
            logger.error(f"GitHub API error: {e}", exc_info=True)
            return [
                SecurityFinding(
                    severity="info",
                    summary="GitHub API error",
                    threat_category="API Error",
                    details=f"Error: {str(e)}, Status: {e.status if hasattr(e, 'status') else 'N/A'}",
                    analyzer="CodeLLMAnalyzer",
                )
            ]
        except Exception as e:
            logger.error(f"Error analyzing repository {repo_url}: {e}", exc_info=True)
            findings.append(
                SecurityFinding(
                    severity="info",
                    summary="Error during repository analysis",
                    threat_category="Error",
                    details=str(e),
                    analyzer="CodeLLMAnalyzer",
                )
            )

        return findings
