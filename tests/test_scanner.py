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

# tests/test_scanner.py

import pytest
import respx
from unittest.mock import patch, AsyncMock, MagicMock
from pydantic import BaseModel
from typing import List, Dict, Any

from mcpscanner import Config, Scanner
from mcpscanner import ToolScanResult
from mcpscanner import ApiAnalyzer
from mcpscanner import YaraAnalyzer
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.analyzers.base import BaseAnalyzer
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.auth import Auth, AuthType
from mcpscanner.core.mcp_models import StdioServer
from mcpscanner.core.result import PromptScanResult, ResourceScanResult
from mcpscanner.core.exceptions import (
    MCPConnectionError,
    MCPAuthenticationError,
    MCPServerNotFoundError,
)


# Mock MCPTool for testing
class MCPTool(BaseModel):
    """Mock implementation of the MCP Tool class for testing."""

    name: str
    description: str
    parameters: List[Dict[str, Any]] = []
    inputSchema: Dict[str, Any] = {}
    # Add any other required fields with default values


# --- Fixtures ---


@pytest.fixture
def config():
    """Provides a test configuration."""
    return Config(api_key="test_api_key")


@pytest.fixture
def mock_mcp_client():
    """Mocks the entire MCP client connection and session lifecycle."""
    mock_session = AsyncMock()

    class MockToolList:
        tools = [
            MCPTool(name="safe_tool", description="This is a safe tool", parameters=[]),
            MCPTool(
                name="malicious_tool",
                description="<script>alert(1)</script>",
                parameters=[],
            ),
        ]

    mock_session.list_tools.return_value = MockToolList()

    mock_session_cm = AsyncMock()
    mock_session_cm.__aenter__.return_value = mock_session

    mock_client_session_class = MagicMock(return_value=mock_session_cm)

    mock_streams = (AsyncMock(), AsyncMock(), AsyncMock())
    mock_stream_cm = AsyncMock()
    mock_stream_cm.__aenter__.return_value = mock_streams

    # Create the patches but don't apply them yet
    patches = [
        patch("mcpscanner.core.scanner.sse_client", return_value=mock_stream_cm),
        patch(
            "mcpscanner.core.scanner.streamablehttp_client", return_value=mock_stream_cm
        ),
        patch("mcpscanner.core.scanner.ClientSession", mock_client_session_class),
    ]

    # Start all patches
    for p in patches:
        p.start()

    # Return the session for tests to use
    yield mock_session

    # Stop all patches after the test
    for p in patches:
        p.stop()


# --- Test Cases ---


@respx.mock
@pytest.mark.asyncio
async def test_scanner_initialization(config):
    """Test the Scanner class initialization."""
    scanner = Scanner(config)
    assert scanner._config == config
    assert isinstance(scanner._api_analyzer, ApiAnalyzer)
    assert isinstance(scanner._yara_analyzer, YaraAnalyzer)


@respx.mock
@pytest.mark.asyncio
async def test_scan_remote_server_tool_method(config):
    """Test the scan_remote_server_tool method of the Scanner class."""
    # Create mock session and tool
    mock_session = AsyncMock()
    mock_tool = MCPTool(
        name="safe_tool", description="This is a safe tool", parameters=[]
    )

    # Setup the mock session to return our mock tool
    class MockToolList:
        tools = [mock_tool]

    mock_session.list_tools.return_value = MockToolList()

    # Mock the _get_mcp_session method to return the client_context and session
    mock_get_session = AsyncMock()
    mock_get_session.return_value = (AsyncMock(), mock_session)

    # Mock _analyze_tool method to return a successful result
    with (
        patch("mcpscanner.core.scanner.Scanner._analyze_tool") as mock_analyze_tool,
        patch(
            "mcpscanner.core.scanner.Scanner._get_mcp_session",
            return_value=mock_get_session.return_value,
        ),
    ):

        mock_analyze_tool.return_value = ToolScanResult(
            tool_name="safe_tool",
            tool_description="This is a safe tool",
            status="completed",
            analyzers=["API"],
            findings=[],
        )

        scanner = Scanner(config)
        result = await scanner.scan_remote_server_tool(
            "https://test-server.com",
            "safe_tool",
            analyzers=[AnalyzerEnum.API, AnalyzerEnum.YARA],
        )

        # Verify the result
        assert result.tool_name == "safe_tool"
        assert result.status == "completed"
        assert len(result.findings) == 0
        assert result.is_safe == True

        # Verify that _analyze_tool was called with the correct tool
        mock_analyze_tool.assert_called_once_with(
            mock_tool, [AnalyzerEnum.API, AnalyzerEnum.YARA], None
        )


@respx.mock
@pytest.mark.asyncio
async def test_scan_remote_server_tool_not_found(config):
    """Test the scan_remote_server_tool method with a non-existent tool."""
    # Create mock session with no tools that match our search
    mock_session = AsyncMock()

    # Setup the mock session to return an empty tool list
    class MockToolList:
        tools = [MCPTool(name="other_tool", description="Some tool", parameters=[])]

    mock_session.list_tools.return_value = MockToolList()

    # Mock the _get_mcp_session method to return the client_context and session
    mock_get_session = AsyncMock()
    mock_get_session.return_value = (AsyncMock(), mock_session)

    # Patch the _get_mcp_session method to return our mock session
    with patch(
        "mcpscanner.core.scanner.Scanner._get_mcp_session",
        return_value=mock_get_session.return_value,
    ):
        scanner = Scanner(config)

        with pytest.raises(ValueError, match="not found on the server"):
            await scanner.scan_remote_server_tool(
                "https://test-server.com", "non_existent_tool"
            )


@respx.mock
@pytest.mark.asyncio
async def test_scan_remote_server_tool_no_server_url(config):
    """Test the scan_remote_server_tool method with an empty server URL."""
    scanner = Scanner(config)

    with pytest.raises(ValueError, match="No server URL provided"):
        await scanner.scan_remote_server_tool("", "test_tool")


@respx.mock
@pytest.mark.asyncio
async def test_scan_remote_server_tools_method(config):
    """Test the scan_remote_server_tools method of the Scanner class."""
    # Create mock session and tools
    mock_session = AsyncMock()
    mock_tools = [
        MCPTool(name="tool1", description="Tool 1", parameters=[]),
        MCPTool(name="tool2", description="Tool 2", parameters=[]),
    ]

    # Setup the mock session to return our mock tools
    class MockToolList:
        tools = mock_tools

    mock_session.list_tools.return_value = MockToolList()

    # Mock the _get_mcp_session method to return the client_context and session
    mock_get_session = AsyncMock()
    mock_get_session.return_value = (AsyncMock(), mock_session)

    # Mock _analyze_tool method to return a successful result
    with (
        patch("mcpscanner.core.scanner.Scanner._analyze_tool") as mock_analyze_tool,
        patch(
            "mcpscanner.core.scanner.Scanner._get_mcp_session",
            return_value=mock_get_session.return_value,
        ),
    ):

        # Configure mock_analyze_tool to return a different result for each tool
        mock_analyze_tool.side_effect = [
            ToolScanResult(
                tool_name="tool1",
                tool_description="Tool 1",
                status="completed",
                analyzers=["API"],
                findings=[],
            ),
            ToolScanResult(
                tool_name="tool2",
                tool_description="Tool 2",
                status="completed",
                analyzers=["API"],
                findings=[],
            ),
        ]

        scanner = Scanner(config)
        results = await scanner.scan_remote_server_tools(
            "https://test-server.com",
            analyzers=[AnalyzerEnum.API, AnalyzerEnum.YARA],
        )

        # Should have results for both tools
        assert len(results) == 2

        # Verify the results match our expected values
        assert results[0].tool_name == "tool1"
        assert results[1].tool_name == "tool2"
        assert all(result.status == "completed" for result in results)
        assert all(len(result.findings) == 0 for result in results)
        assert all(result.is_safe for result in results)

        # Verify _analyze_tool was called for each tool
        assert mock_analyze_tool.call_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_scan_remote_server_tools_no_server_url(config):
    """Test the scan_remote_server_tools method with an empty server URL."""
    scanner = Scanner(config)

    with pytest.raises(ValueError, match="No server URL provided"):
        await scanner.scan_remote_server_tools("")


# Mock custom analyzer for testing
class MockCustomAnalyzer(BaseAnalyzer):
    """Mock custom analyzer for testing."""

    def __init__(self, name: str = "mock_analyzer", should_fail: bool = False):
        super().__init__(name)  # Properly call parent constructor
        self.should_fail = should_fail

    async def analyze(
        self, content: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Mock analyze method."""
        if self.should_fail:
            raise Exception("Mock analyzer failure")

        if "malicious" in content.lower():
            return [
                self.create_security_finding(
                    severity="HIGH",
                    summary="Mock finding: malicious content detected",
                    threat_category="MOCK_THREAT",
                    details={"content": content},
                )
            ]
        return []


# --- Additional Test Cases ---


@pytest.mark.asyncio
async def test_scanner_initialization_with_custom_analyzers(config):
    """Test Scanner initialization with custom analyzers."""
    custom_analyzer = MockCustomAnalyzer("test_analyzer")
    scanner = Scanner(config, custom_analyzers=[custom_analyzer])

    assert scanner._config == config
    assert len(scanner.get_custom_analyzers()) == 1
    assert scanner.get_custom_analyzers()[0].name == "test_analyzer"


@pytest.mark.asyncio
async def test_scanner_initialization_without_api_key():
    """Test Scanner initialization without API key."""
    config = Config()  # No API key
    scanner = Scanner(config)

    assert scanner._config == config
    assert scanner._api_analyzer is None
    assert scanner._yara_analyzer is not None


@pytest.mark.asyncio
async def test_validate_analyzer_requirements_success(config):
    """Test successful analyzer requirements validation."""
    scanner = Scanner(config)
    # Should not raise any exception
    scanner._validate_analyzer_requirements([AnalyzerEnum.YARA])


@pytest.mark.asyncio
async def test_validate_analyzer_requirements_missing_api_key():
    """Test analyzer requirements validation with missing API key."""
    config = Config()  # No API key
    scanner = Scanner(config)

    with pytest.raises(
        ValueError,
        match="API analyzer requested but MCP_SCANNER_API_KEY not configured",
    ):
        scanner._validate_analyzer_requirements([AnalyzerEnum.API])


@pytest.mark.asyncio
async def test_validate_analyzer_requirements_missing_llm_key():
    """Test analyzer requirements validation with missing LLM key."""
    config = Config(api_key="test_key")  # No LLM key
    scanner = Scanner(config)

    with pytest.raises(
        ValueError,
        match="LLM analyzer requested but MCP_SCANNER_LLM_API_KEY not configured",
    ):
        scanner._validate_analyzer_requirements([AnalyzerEnum.LLM])


@pytest.mark.asyncio
async def test_analyze_tool_with_api_analyzer(config):
    """Test _analyze_tool method with API analyzer."""
    mock_tool = MCPTool(name="test_tool", description="Test description")

    with patch.object(ApiAnalyzer, "analyze") as mock_api_analyze:
        mock_api_analyze.return_value = [
            SecurityFinding(
                severity="medium",
                summary="API finding",
                analyzer="api",
                threat_category="API_FINDING",
                details={},
            )
        ]

        scanner = Scanner(config)
        result = await scanner._analyze_tool(mock_tool, [AnalyzerEnum.API])

        assert result.tool_name == "test_tool"
        assert result.tool_description == "Test description"
        assert len(result.findings) == 1
        assert result.findings[0].analyzer == "API"
        mock_api_analyze.assert_called_once()


@pytest.mark.asyncio
async def test_analyze_tool_with_yara_analyzer(config):
    """Test _analyze_tool method with YARA analyzer."""
    mock_tool = MCPTool(name="test_tool", description="Test description")

    with patch.object(YaraAnalyzer, "analyze") as mock_yara_analyze:
        mock_yara_analyze.return_value = [
            SecurityFinding(
                severity="high",
                summary="YARA finding",
                analyzer="YARA",
                threat_category="YARA_DETECTION",
                details={},
            )
        ]

        scanner = Scanner(config)
        result = await scanner._analyze_tool(mock_tool, [AnalyzerEnum.YARA])

        assert result.tool_name == "test_tool"
        assert (
            len(result.findings) >= 1
        )  # YARA analyzer may analyze multiple parts (description, parameters)
        # Check that at least one finding has the expected analyzer
        yara_findings = [f for f in result.findings if f.analyzer == "YARA"]
        assert len(yara_findings) >= 1
        mock_yara_analyze.assert_called()


@pytest.mark.asyncio
async def test_analyze_tool_with_custom_analyzer(config):
    """Test _analyze_tool method with custom analyzer."""
    mock_tool = MCPTool(name="test_tool", description="malicious content")
    custom_analyzer = MockCustomAnalyzer("custom_test")

    scanner = Scanner(config, custom_analyzers=[custom_analyzer])
    result = await scanner._analyze_tool(mock_tool, [])

    assert result.tool_name == "test_tool"
    assert len(result.findings) == 1
    assert result.findings[0].analyzer == "custom_test"
    assert result.findings[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_analyze_tool_with_failing_analyzer(config):
    """Test _analyze_tool method with failing analyzer."""
    mock_tool = MCPTool(name="test_tool", description="Test description")
    failing_analyzer = MockCustomAnalyzer("failing_analyzer", should_fail=True)

    scanner = Scanner(config, custom_analyzers=[failing_analyzer])
    # Should not raise exception, just log error
    result = await scanner._analyze_tool(mock_tool, [])

    assert result.tool_name == "test_tool"
    assert len(result.findings) == 0  # No findings due to failure


@pytest.mark.asyncio
async def test_analyze_tool_with_http_headers(config):
    """Test _analyze_tool method with HTTP headers."""
    mock_tool = MCPTool(name="test_tool", description="Test description")
    custom_analyzer = MockCustomAnalyzer("header_test")

    scanner = Scanner(config, custom_analyzers=[custom_analyzer])
    headers = {"Authorization": "Bearer test-token"}

    with patch.object(custom_analyzer, "analyze") as mock_analyze:
        mock_analyze.return_value = []

        await scanner._analyze_tool(mock_tool, [], http_headers=headers)

        # Verify headers were passed to custom analyzer
        call_args = mock_analyze.call_args
        context = call_args[0][1]  # Second argument is context
        assert "http_headers" in context
        assert context["http_headers"] == headers


@pytest.mark.asyncio
async def test_get_mcp_session_no_auth(config):
    """Test _get_mcp_session without authentication."""
    scanner = Scanner(config)

    with (
        patch("mcpscanner.core.scanner.sse_client") as mock_sse_client,
        patch("mcpscanner.core.scanner.ClientSession") as mock_client_session,
    ):

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = (AsyncMock(), AsyncMock())
        mock_sse_client.return_value = mock_context

        mock_session = AsyncMock()
        mock_session.__aenter__.return_value = mock_session
        mock_client_session.return_value = mock_session

        client_context, session = await scanner._get_mcp_session("https://test.com/sse")

        assert client_context is not None
        assert session is not None
        mock_sse_client.assert_called_once_with("https://test.com/sse")


@pytest.mark.asyncio
async def test_get_mcp_session_with_bearer_auth(config):
    """Test _get_mcp_session with Bearer authentication."""
    scanner = Scanner(config)
    auth = Auth(enabled=True, auth_type=AuthType.BEARER, bearer_token="test-token")

    with (
        patch("mcpscanner.core.scanner.sse_client") as mock_sse_client,
        patch("mcpscanner.core.scanner.ClientSession") as mock_client_session,
    ):

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = (AsyncMock(), AsyncMock())
        mock_sse_client.return_value = mock_context

        mock_session = AsyncMock()
        mock_session.__aenter__.return_value = mock_session
        mock_client_session.return_value = mock_session

        await scanner._get_mcp_session("https://test.com/sse", auth)

        # Verify headers were passed
        call_args = mock_sse_client.call_args
        assert "headers" in call_args.kwargs
        assert call_args.kwargs["headers"]["Authorization"] == "Bearer test-token"


@pytest.mark.asyncio
async def test_get_mcp_session_connection_error(config):
    """Test _get_mcp_session with connection error."""
    scanner = Scanner(config)

    with patch("mcpscanner.core.scanner.sse_client") as mock_sse_client:
        mock_context = AsyncMock()
        # Simulate a connection error that will be caught and converted
        mock_context.__aenter__.side_effect = Exception("nodename nor servname provided")
        mock_sse_client.return_value = mock_context

        with pytest.raises(MCPConnectionError, match="Unable to connect to MCP server"):
            await scanner._get_mcp_session("https://test.com/sse")


@pytest.mark.asyncio
async def test_close_mcp_session(config):
    """Test _close_mcp_session method."""
    scanner = Scanner(config)

    mock_session = AsyncMock()
    mock_context = AsyncMock()

    # Should not raise any exceptions
    await scanner._close_mcp_session(mock_context, mock_session)

    mock_session.__aexit__.assert_called_once()
    mock_context.__aexit__.assert_called_once()


@pytest.mark.asyncio
async def test_close_mcp_session_with_errors(config):
    """Test _close_mcp_session method with errors."""
    scanner = Scanner(config)

    mock_session = AsyncMock()
    mock_session.__aexit__.side_effect = Exception("Session close error")

    mock_context = AsyncMock()
    mock_context.__aexit__.side_effect = Exception("Context close error")

    # Should not raise exceptions, just log warnings
    await scanner._close_mcp_session(mock_context, mock_session)


@pytest.mark.asyncio
async def test_scan_stdio_server_tools(config):
    """Test scan_stdio_server_tools method."""
    server_config = StdioServer(command="python", args=["-m", "test_server"])

    mock_session = AsyncMock()
    mock_tools = [
        MCPTool(name="stdio_tool1", description="Tool 1"),
        MCPTool(name="stdio_tool2", description="Tool 2"),
    ]

    class MockToolList:
        tools = mock_tools

    mock_session.list_tools.return_value = MockToolList()

    with (
        patch.object(Scanner, "_get_stdio_session") as mock_get_session,
        patch.object(Scanner, "_analyze_tool") as mock_analyze_tool,
    ):

        mock_get_session.return_value = (AsyncMock(), mock_session)
        mock_analyze_tool.side_effect = [
            ToolScanResult(
                tool_name="stdio_tool1",
                tool_description="Tool 1",
                status="completed",
                analyzers=["API"],
                findings=[],
            ),
            ToolScanResult(
                tool_name="stdio_tool2",
                tool_description="Tool 2",
                status="completed",
                analyzers=["API"],
                findings=[],
            ),
        ]

        scanner = Scanner(config)
        results = await scanner.scan_stdio_server_tools(
            server_config, [AnalyzerEnum.YARA]
        )

        assert len(results) == 2
        assert results[0].tool_name == "stdio_tool1"
        assert results[1].tool_name == "stdio_tool2"


@pytest.mark.asyncio
async def test_scan_stdio_server_tools_no_command(config):
    """Test scan_stdio_server_tools with no command."""
    server_config = StdioServer(command="")
    scanner = Scanner(config)

    # The scanner will try to connect before validating command, so we expect MCPConnectionError
    with pytest.raises(MCPConnectionError, match="Unable to connect to stdio MCP server"):
        await scanner.scan_stdio_server_tools(
            server_config, analyzers=[AnalyzerEnum.YARA]
        )


@pytest.mark.asyncio
async def test_scan_stdio_server_tool(config):
    """Test scan_stdio_server_tool method."""
    server_config = StdioServer(command="python", args=["-m", "test_server"])

    mock_session = AsyncMock()
    mock_tool = MCPTool(name="target_tool", description="Target tool")

    class MockToolList:
        tools = [mock_tool]

    mock_session.list_tools.return_value = MockToolList()

    with (
        patch.object(Scanner, "_get_stdio_session") as mock_get_session,
        patch.object(Scanner, "_analyze_tool") as mock_analyze_tool,
    ):

        mock_get_session.return_value = (AsyncMock(), mock_session)
        mock_analyze_tool.return_value = ToolScanResult(
            tool_name="target_tool",
            tool_description="Target tool",
            status="completed",
            analyzers=["API"],
            findings=[],
        )

        scanner = Scanner(config)
        result = await scanner.scan_stdio_server_tool(
            server_config, "target_tool", [AnalyzerEnum.YARA]
        )

        assert result.tool_name == "target_tool"
        assert result.status == "completed"


@pytest.mark.asyncio
async def test_scan_stdio_server_tool_not_found(config):
    """Test scan_stdio_server_tool with tool not found."""
    server_config = StdioServer(command="python", args=["-m", "test_server"])

    mock_session = AsyncMock()

    class MockToolList:
        tools = [MCPTool(name="other_tool", description="Other tool")]

    mock_session.list_tools.return_value = MockToolList()

    with patch.object(Scanner, "_get_stdio_session") as mock_get_session:
        mock_get_session.return_value = (AsyncMock(), mock_session)

        scanner = Scanner(config)

        with pytest.raises(ValueError, match="not found on the stdio server"):
            await scanner.scan_stdio_server_tool(
                server_config,
                "missing_tool",
                analyzers=[AnalyzerEnum.API, AnalyzerEnum.YARA],
            )


@pytest.mark.asyncio
async def test_scan_remote_server_tool_with_auth(config):
    """Test scan_remote_server_tool with authentication."""
    auth = Auth(enabled=True, auth_type=AuthType.BEARER, bearer_token="test-token")

    mock_session = AsyncMock()
    mock_tool = MCPTool(name="auth_tool", description="Authenticated tool")

    class MockToolList:
        tools = [mock_tool]

    mock_session.list_tools.return_value = MockToolList()

    with (
        patch.object(Scanner, "_get_mcp_session") as mock_get_session,
        patch.object(Scanner, "_analyze_tool") as mock_analyze_tool,
    ):

        mock_get_session.return_value = (AsyncMock(), mock_session)
        mock_analyze_tool.return_value = ToolScanResult(
            tool_name="auth_tool",
            tool_description="Authenticated tool",
            status="completed",
            analyzers=["API"],
            findings=[],
        )

        scanner = Scanner(config)
        result = await scanner.scan_remote_server_tool(
            "https://test.com", "auth_tool", auth=auth, analyzers=[AnalyzerEnum.YARA]
        )

        assert result.tool_name == "auth_tool"
        mock_get_session.assert_called_once_with("https://test.com", auth)


@pytest.mark.asyncio
async def test_scan_remote_server_tools_with_http_headers(config):
    """Test scan_remote_server_tools with HTTP headers."""
    mock_session = AsyncMock()
    mock_tools = [MCPTool(name="header_tool", description="Tool with headers")]

    class MockToolList:
        tools = mock_tools

    mock_session.list_tools.return_value = MockToolList()

    with (
        patch.object(Scanner, "_get_mcp_session") as mock_get_session,
        patch.object(Scanner, "_analyze_tool") as mock_analyze_tool,
    ):

        mock_get_session.return_value = (AsyncMock(), mock_session)
        mock_analyze_tool.return_value = ToolScanResult(
            tool_name="header_tool",
            tool_description="Tool with headers",
            status="completed",
            analyzers=["API"],
            findings=[],
        )

        scanner = Scanner(config)
        headers = {"X-Custom-Header": "test-value"}
        results = await scanner.scan_remote_server_tools(
            "https://test.com", analyzers=[AnalyzerEnum.YARA], http_headers=headers
        )

        assert len(results) == 1
        # Verify headers were passed to _analyze_tool
        mock_analyze_tool.assert_called_once()
        call_args = mock_analyze_tool.call_args
        assert call_args[0][2] == headers  # Third argument is http_headers


@pytest.mark.asyncio
async def test_get_mcp_session_401_unauthorized_streamable_http(config):
    """Test _get_mcp_session with 401 authentication error for streamable HTTP endpoint."""
    scanner = Scanner(config)

    with patch("mcpscanner.core.scanner.streamablehttp_client") as mock_client:
        mock_context = AsyncMock()

        # Create a mock HTTPStatusError with 401
        class MockHTTPStatusError(Exception):
            def __init__(self):
                super().__init__("Client error '401 Unauthorized' for url 'https://api.mcpanalytics.ai/auth0'")

        # BaseExceptionGroup with 401 error (simulates what MCP library does)
        error_group = BaseExceptionGroup(
            "unhandled errors",
            [MockHTTPStatusError()]
        )

        mock_context.__aenter__.side_effect = error_group
        mock_client.return_value = mock_context

        with pytest.raises(MCPAuthenticationError, match="Authentication failed.*OAuth or Bearer token"):
            await scanner._get_mcp_session("https://api.mcpanalytics.ai/auth0")


@pytest.mark.asyncio
async def test_get_mcp_session_401_unauthorized_via_exception_group(config):
    """Test _get_mcp_session with 401 authentication error via BaseExceptionGroup (SSE endpoint)."""
    scanner = Scanner(config)

    with patch("mcpscanner.core.scanner.sse_client") as mock_sse_client:
        mock_context = AsyncMock()

        # Create a mock HTTPStatusError
        class MockHTTPStatusError(Exception):
            def __init__(self):
                super().__init__("Client error '401 Unauthorized' for url 'https://api.mcpanalytics.ai/auth0/sse'")

        # BaseExceptionGroup with 401 error
        error_group = BaseExceptionGroup(
            "unhandled errors",
            [MockHTTPStatusError()]
        )

        mock_context.__aenter__.side_effect = error_group
        mock_sse_client.return_value = mock_context

        with pytest.raises(MCPAuthenticationError, match="Authentication failed.*OAuth or Bearer token"):
            await scanner._get_mcp_session("https://api.mcpanalytics.ai/auth0/sse")


@pytest.mark.asyncio
async def test_get_mcp_session_403_forbidden(config):
    """Test _get_mcp_session with 403 forbidden error."""
    scanner = Scanner(config)

    with patch("mcpscanner.core.scanner.streamablehttp_client") as mock_client:
        mock_context = AsyncMock()

        class MockHTTPStatusError(Exception):
            def __init__(self):
                super().__init__("Client error '403 Forbidden' for url 'https://api.mcpanalytics.ai/auth0'")

        error_group = BaseExceptionGroup(
            "unhandled errors",
            [MockHTTPStatusError()]
        )

        mock_context.__aenter__.side_effect = error_group
        mock_client.return_value = mock_context

        with pytest.raises(MCPAuthenticationError, match="Access denied.*authentication credentials"):
            await scanner._get_mcp_session("https://api.mcpanalytics.ai/auth0")


@pytest.mark.asyncio
async def test_get_mcp_session_404_not_found(config):
    """Test _get_mcp_session with 404 not found error."""
    scanner = Scanner(config)

    with patch("mcpscanner.core.scanner.streamablehttp_client") as mock_client:
        mock_context = AsyncMock()

        class MockHTTPStatusError(Exception):
            def __init__(self):
                super().__init__("Client error '404 Not Found' for url 'https://api.mcpanalytics.ai/nonexistent'")

        error_group = BaseExceptionGroup(
            "unhandled errors",
            [MockHTTPStatusError()]
        )

        mock_context.__aenter__.side_effect = error_group
        mock_client.return_value = mock_context

        with pytest.raises(MCPServerNotFoundError, match="MCP server endpoint not found.*verify the URL"):
            await scanner._get_mcp_session("https://api.mcpanalytics.ai/nonexistent")


# Note: DNS resolution failure test is covered by manual testing with https://test.alpic.ai
# The CancelledError path is difficult to mock reliably due to the async context manager setup


# --- Prompt Scanning Tests ---


def test_prompt_scan_result_creation():
    """Test creating a PromptScanResult."""
    result = PromptScanResult(
        prompt_name="test_prompt",
        prompt_description="A test prompt",
        status="completed",
        analyzers=[AnalyzerEnum.API],
        findings=[]
    )

    assert result.prompt_name == "test_prompt"
    assert result.prompt_description == "A test prompt"
    assert result.status == "completed"
    assert result.is_safe is True
    assert len(result.findings) == 0


def test_prompt_scan_result_with_findings():
    """Test PromptScanResult with security findings."""
    finding = SecurityFinding(
        severity="HIGH",
        summary="Test finding",
        analyzer="API",
        threat_category="MALICIOUS_CODE",
        details={}
    )

    result = PromptScanResult(
        prompt_name="unsafe_prompt",
        prompt_description="An unsafe prompt",
        status="completed",
        analyzers=[AnalyzerEnum.API],
        findings=[finding]
    )

    assert result.is_safe is False
    assert len(result.findings) == 1
    assert result.findings[0].severity == "HIGH"


def test_prompt_scan_result_failed_status():
    """Test PromptScanResult with failed status."""
    result = PromptScanResult(
        prompt_name="failed_prompt",
        prompt_description="A failed prompt scan",
        status="failed",
        analyzers=[],
        findings=[]
    )

    assert result.status == "failed"
    assert result.is_safe is True  # No findings means safe


# --- Resource Scanning Tests ---


def test_resource_scan_result_creation():
    """Test creating a ResourceScanResult."""
    result = ResourceScanResult(
        resource_uri="file://test/file.txt",
        resource_name="test_file",
        resource_mime_type="text/plain",
        status="completed",
        analyzers=[AnalyzerEnum.API],
        findings=[]
    )

    assert result.resource_uri == "file://test/file.txt"
    assert result.resource_name == "test_file"
    assert result.resource_mime_type == "text/plain"
    assert result.status == "completed"
    assert result.is_safe is True
    assert len(result.findings) == 0


def test_resource_scan_result_with_findings():
    """Test ResourceScanResult with security findings."""
    finding = SecurityFinding(
        severity="HIGH",
        summary="Malicious content detected",
        analyzer="LLM",
        threat_category="XSS",
        details={"threat_type": "XSS"}
    )

    result = ResourceScanResult(
        resource_uri="file://test/malicious.html",
        resource_name="malicious_file",
        resource_mime_type="text/html",
        status="completed",
        analyzers=[AnalyzerEnum.LLM],
        findings=[finding]
    )

    assert result.is_safe is False
    assert len(result.findings) == 1
    assert result.findings[0].severity == "HIGH"


def test_resource_scan_result_skipped_status():
    """Test ResourceScanResult with skipped status."""
    result = ResourceScanResult(
        resource_uri="file://test/binary.bin",
        resource_name="binary_file",
        resource_mime_type="application/octet-stream",
        status="skipped",
        analyzers=[],
        findings=[]
    )

    assert result.status == "skipped"
    assert result.is_safe is True  # No findings means safe, even if skipped


def test_resource_scan_result_failed_status():
    """Test ResourceScanResult with failed status."""
    result = ResourceScanResult(
        resource_uri="file://test/error.txt",
        resource_name="error_file",
        resource_mime_type="text/plain",
        status="failed",
        analyzers=[],
        findings=[]
    )

    assert result.status == "failed"
    assert result.is_safe is True  # No findings means safe, even if failed
