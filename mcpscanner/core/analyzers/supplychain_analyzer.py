"""Supply Chain Analyzer for MCP Scanner.

This analyzer uses the mcp-supplychain engine to detect mismatches between
MCP tool docstrings and their actual code behavior using deep code analysis
and LLM-based comparison.
"""

import os
from pathlib import Path
from typing import Any, Dict, List
from ...config.config import Config
from ...utils.logging_config import get_logger
from .base import BaseAnalyzer, SecurityFinding
from .mcp_docstring_analyzer import MCPDocstringAnalyzer

logger = get_logger(__name__)


class SupplyChainAnalyzer(BaseAnalyzer):
    """Analyzer that detects docstring/behavior mismatches in MCP tool source code.
    
    This analyzer:
    1. Extracts MCP tool source code from the server
    2. Performs deep dataflow analysis using the supplychain engine
    3. Uses LLM to compare docstring claims vs actual behavior
    4. Detects hidden behaviors like data exfiltration
    """

    def __init__(self, config: Config):
        """Initialize the SupplyChainAnalyzer.
        
        Args:
            config: Configuration containing LLM credentials
        """
        super().__init__(name="SupplyChain")
        self._config = config
        self._docstring_analyzer = MCPDocstringAnalyzer(config)
        logger.info("SupplyChainAnalyzer initialized with LLM-based analysis")

    async def analyze(
        self, content: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze MCP tool source code for docstring/behavior mismatches.
        
        Args:
            content: File path to Python file/directory OR source code string
            context: Analysis context with tool_name, file_path, etc.
            
        Returns:
            List of SecurityFinding objects for detected mismatches
        """
        try:
            all_findings = []
            
            # Check if content is a directory
            if os.path.isdir(content):
                logger.info(f"Scanning directory: {content}")
                python_files = self._find_python_files(content)
                logger.info(f"Found {len(python_files)} Python file(s) to analyze")
                
                for py_file in python_files:
                    logger.info(f"Analyzing file: {py_file}")
                    file_findings = await self._analyze_file(py_file, context)
                    all_findings.extend(file_findings)
                    
            # Check if content is a single file
            elif os.path.isfile(content):
                all_findings = await self._analyze_file(content, context)
                
            else:
                # Content is source code string
                findings = await self._docstring_analyzer.analyze(content, context)
                for finding in findings:
                    finding.analyzer = "SupplyChain"
                all_findings = findings
            
            logger.info(
                f"SupplyChain analysis complete: {len(all_findings)} finding(s) detected"
            )
            return all_findings
            
        except Exception as e:
            logger.error(f"SupplyChain analysis failed: {e}")
            return []
    
    def _find_python_files(self, directory: str) -> List[str]:
        """Find all Python files in a directory.
        
        Args:
            directory: Directory path to search
            
        Returns:
            List of Python file paths
        """
        python_files = []
        path = Path(directory)
        
        # Recursively find all .py files
        for py_file in path.rglob("*.py"):
            # Skip __pycache__ and hidden directories
            if "__pycache__" not in str(py_file) and not any(
                part.startswith(".") for part in py_file.parts
            ):
                python_files.append(str(py_file))
        
        return sorted(python_files)
    
    async def _analyze_file(self, file_path: str, context: Dict[str, Any]) -> List[SecurityFinding]:
        """Analyze a single Python file.
        
        Args:
            file_path: Path to Python file
            context: Analysis context
            
        Returns:
            List of SecurityFinding objects
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            file_context = context.copy()
            file_context['file_path'] = file_path
            
            findings = await self._docstring_analyzer.analyze(source_code, file_context)
            
            # Tag findings with SupplyChain analyzer name and file path
            for finding in findings:
                finding.analyzer = "SupplyChain"
                if finding.details:
                    finding.details['source_file'] = file_path
            
            return findings
            
        except Exception as e:
            logger.error(f"Failed to analyze {file_path}: {e}")
            return []
