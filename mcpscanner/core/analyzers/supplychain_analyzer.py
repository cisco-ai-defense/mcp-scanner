"""Supply Chain Analyzer for MCP Scanner.

This analyzer uses the mcp-supplychain engine to detect mismatches between
MCP tool docstrings and their actual code behavior using deep code analysis
and LLM-based comparison.
"""

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
            content: File path to Python MCP server code OR source code string
            context: Analysis context with tool_name, file_path, etc.
            
        Returns:
            List of SecurityFinding objects for detected mismatches
        """
        try:
            # Check if content is a file path
            import os
            if os.path.isfile(content):
                # Read the file
                with open(content, 'r', encoding='utf-8') as f:
                    source_code = f.read()
                context['file_path'] = content
            else:
                # Content is already source code
                source_code = content
            
            # Use the MCPDocstringAnalyzer which has all the supplychain logic
            findings = await self._docstring_analyzer.analyze(source_code, context)
            
            # Tag findings with SupplyChain analyzer name
            for finding in findings:
                finding.analyzer = "SupplyChain"
            
            logger.info(
                f"SupplyChain analysis complete: {len(findings)} finding(s) detected"
            )
            return findings
            
        except Exception as e:
            logger.error(f"SupplyChain analysis failed: {e}")
            return []
