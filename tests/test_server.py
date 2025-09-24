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

"""Unit tests for server module."""

import pytest
import sys
import tempfile
import logging
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from argparse import Namespace

from mcpscanner.server import main


class TestServerMain:
    """Test cases for server main function."""

    @pytest.fixture
    def mock_uvicorn_run(self):
        """Mock uvicorn.run to prevent actual server startup."""
        with patch("mcpscanner.server.uvicorn.run") as mock_run:
            yield mock_run

    @pytest.fixture
    def mock_load_dotenv(self):
        """Mock dotenv.load_dotenv."""
        with patch("mcpscanner.server.load_dotenv") as mock_load:
            yield mock_load

    @pytest.fixture
    def mock_logger(self):
        """Mock logger."""
        with patch("mcpscanner.server.logger") as mock_log:
            yield mock_log

    def test_main_default_arguments(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with default arguments."""
        with patch("sys.argv", ["server.py"]):
            with patch.dict("os.environ", {}, clear=True):
                main()

                # Verify dotenv was loaded
                mock_load_dotenv.assert_called()

                # Verify uvicorn.run was called with defaults
                mock_uvicorn_run.assert_called_once_with(
                    "mcpscanner.api.api:app", host="127.0.0.1", port=8000, reload=False
                )

    def test_main_custom_arguments(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with custom arguments."""
        with patch(
            "sys.argv",
            [
                "server.py",
                "--host",
                "127.0.0.1",
                "--port",
                "9000",
                "--reload",
                "--debug",
            ],
        ):
            with patch.dict("os.environ", {}, clear=True):
                main()

                # Verify uvicorn.run was called with custom values
                mock_uvicorn_run.assert_called_once_with(
                    "mcpscanner.api.api:app", host="127.0.0.1", port=9000, reload=True
                )

    def test_main_with_env_file(self, mock_uvicorn_run, mock_load_dotenv, mock_logger):
        """Test main function with custom env file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            env_file = f.name
            f.write("MCP_SCANNER_API_KEY=test_key\n")

        try:
            with patch("sys.argv", ["server.py", "--env-file", env_file]):
                with patch.dict("os.environ", {}, clear=True):
                    main()

                    # Verify dotenv was loaded twice (once default, once custom)
                    assert mock_load_dotenv.call_count == 2
                    mock_load_dotenv.assert_has_calls(
                        [call(), call(env_file)]  # Default call  # Custom env file
                    )
        finally:
            Path(env_file).unlink(missing_ok=True)

    def test_main_with_nonexistent_env_file(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with nonexistent env file."""
        with patch("sys.argv", ["server.py", "--env-file", "/nonexistent/.env"]):
            with patch.dict("os.environ", {}, clear=True):
                main()

                # Verify dotenv was only called once (default)
                mock_load_dotenv.assert_called_once_with()

    def test_main_with_api_key_configured(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with API key configured."""
        with patch("sys.argv", ["server.py"]):
            with patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_api_key"}):
                main()

                # Verify success message was logged
                mock_logger.debug.assert_any_call(
                    "Cisco AI Defense API key configured successfully."
                )

    def test_main_without_api_key(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function without API key configured."""
        with patch("sys.argv", ["server.py"]):
            with patch.dict("os.environ", {}, clear=True):
                main()

                # Verify warning messages were logged
                mock_logger.warning.assert_any_call(
                    "MCP_SCANNER_API_KEY is not set. Cisco AI Defense API analyzer will not work."
                )
                mock_logger.warning.assert_any_call(
                    "Please set MCP_SCANNER_API_KEY in your .env file or environment variables."
                )

    def test_main_with_llm_api_key_configured(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with LLM API key configured."""
        with patch("sys.argv", ["server.py"]):
            with patch.dict("os.environ", {"MCP_SCANNER_LLM_API_KEY": "test_llm_key"}):
                main()

                # Verify success message was logged
                mock_logger.debug.assert_any_call(
                    "LLM API key configured successfully."
                )

    def test_main_without_llm_api_key(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function without LLM API key configured."""
        with patch("sys.argv", ["server.py"]):
            with patch.dict("os.environ", {}, clear=True):
                main()

                # Verify warning messages were logged
                mock_logger.warning.assert_any_call(
                    "MCP_SCANNER_LLM_API_KEY is not set. LLM analyzer will not work."
                )
                mock_logger.warning.assert_any_call(
                    "Please set MCP_SCANNER_LLM_API_KEY in your .env file or environment variables."
                )

    def test_main_endpoint_logging_default(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function logs default endpoint."""
        with patch("sys.argv", ["server.py"]):
            with patch.dict("os.environ", {}, clear=True):
                main()

                # Verify default endpoint was logged
                mock_logger.debug.assert_any_call(
                    "Using endpoint: https://us.api.inspect.aidefense.security.cisco.com/api/v1"
                )

    def test_main_endpoint_logging_custom(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function logs custom endpoint."""
        with patch("sys.argv", ["server.py"]):
            with patch.dict(
                "os.environ", {"MCP_SCANNER_ENDPOINT": "https://custom.endpoint.com"}
            ):
                main()

                # Verify custom endpoint was logged
                mock_logger.debug.assert_any_call(
                    "Using endpoint: https://custom.endpoint.com"
                )

    def test_main_debug_logging_enabled(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with debug logging enabled."""
        with patch("sys.argv", ["server.py", "--debug"]):
            with patch("mcpscanner.server.logging.basicConfig") as mock_basic_config:
                with patch.dict("os.environ", {}, clear=True):
                    main()

                    # Verify debug logging was configured
                    mock_basic_config.assert_called_once_with(
                        level=logging.DEBUG,
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                        stream=sys.stdout,
                    )

                    # Verify debug message was logged
                    mock_logger.debug.assert_any_call(
                        "Debug logging enabled - detailed analyzer logs will be shown"
                    )

    def test_main_info_logging_default(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with default info logging."""
        with patch("sys.argv", ["server.py"]):
            with patch("mcpscanner.server.logging.basicConfig") as mock_basic_config:
                with patch.dict("os.environ", {}, clear=True):
                    main()

                    # Verify info logging was configured
                    mock_basic_config.assert_called_once_with(
                        level=logging.WARNING,
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                        stream=sys.stdout,
                    )

    def test_main_all_keys_configured(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with all API keys configured."""
        with patch("sys.argv", ["server.py"]):
            with patch.dict(
                "os.environ",
                {
                    "MCP_SCANNER_API_KEY": "test_api_key",
                    "MCP_SCANNER_LLM_API_KEY": "test_llm_key",
                    "MCP_SCANNER_ENDPOINT": "https://custom.endpoint.com",
                },
            ):
                main()

                # Verify all success messages were logged
                mock_logger.debug.assert_any_call(
                    "Cisco AI Defense API key configured successfully."
                )
                mock_logger.debug.assert_any_call(
                    "LLM API key configured successfully."
                )
                mock_logger.debug.assert_any_call(
                    "Using endpoint: https://custom.endpoint.com"
                )

    def test_main_argument_parsing_error(self, mock_uvicorn_run, mock_load_dotenv):
        """Test main function with invalid arguments."""
        with patch("sys.argv", ["server.py", "--invalid-arg"]):
            with pytest.raises(SystemExit):
                main()

    def test_main_port_type_conversion(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with port as string that gets converted to int."""
        with patch("sys.argv", ["server.py", "--port", "8080"]):
            with patch.dict("os.environ", {}, clear=True):
                main()

                # Verify port was converted to int
                mock_uvicorn_run.assert_called_once_with(
                    "mcpscanner.api.api:app", host="127.0.0.1", port=8080, reload=False
                )

    def test_main_with_all_custom_args(
        self, mock_uvicorn_run, mock_load_dotenv, mock_logger
    ):
        """Test main function with all custom arguments."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            env_file = f.name

        try:
            with patch(
                "sys.argv",
                [
                    "server.py",
                    "--host",
                    "localhost",
                    "--port",
                    "3000",
                    "--reload",
                    "--env-file",
                    env_file,
                    "--debug",
                ],
            ):
                with patch(
                    "mcpscanner.server.logging.basicConfig"
                ) as mock_basic_config:
                    with patch.dict(
                        "os.environ",
                        {
                            "MCP_SCANNER_API_KEY": "api_key",
                            "MCP_SCANNER_LLM_API_KEY": "llm_key",
                        },
                    ):
                        main()

                        # Verify all configurations
                        mock_uvicorn_run.assert_called_once_with(
                            "mcpscanner.api.api:app",
                            host="localhost",
                            port=3000,
                            reload=True,
                        )

                        # Verify debug logging
                        mock_basic_config.assert_called_once_with(
                            level=logging.DEBUG,
                            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                            stream=sys.stdout,
                        )
        finally:
            Path(env_file).unlink(missing_ok=True)
