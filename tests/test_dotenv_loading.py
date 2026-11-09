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

# tests/test_dotenv_loading.py
import os
import subprocess
import sys
import textwrap

_VARS = ("MCP_SCANNER_ALIGNMENT_MAX_PROMPT_CHARS", "MCP_SCANNER_LLM_TIMEOUT")

# MCPScannerConstants reads its os.getenv() defaults once, when the class is
# defined. Run the import in a fresh interpreter, with load_dotenv stubbed to
# set a value the way a .env file would, and check the constants see it.
_STUBBED_SCRIPT = textwrap.dedent(
    """
    import os
    import dotenv

    def fake_load_dotenv(*args, **kwargs):
        os.environ["MCP_SCANNER_ALIGNMENT_MAX_PROMPT_CHARS"] = "123456"
        os.environ["MCP_SCANNER_LLM_TIMEOUT"] = "321"
        return True

    dotenv.load_dotenv = fake_load_dotenv

    import {module}
    from mcpscanner.config.constants import MCPScannerConstants

    print(MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS)
    print(MCPScannerConstants.DEFAULT_LLM_TIMEOUT)
    """
)

_REAL_SCRIPT = textwrap.dedent(
    """
    import mcpscanner.cli
    from mcpscanner.config.constants import MCPScannerConstants

    print(MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS)
    print(MCPScannerConstants.DEFAULT_LLM_TIMEOUT)
    """
)


def _run_constants_script(script: str, cwd=None, script_path=None) -> list[str]:
    """Run script in a fresh interpreter without the tested variables set.

    With script_path, the script runs from that file, as the mcp-scanner
    console script does; under -c, find_dotenv() treats the session as
    interactive and searches the working directory regardless.

    Returns the printed constants, one per line.
    """
    env = {k: v for k, v in os.environ.items() if k not in _VARS}
    if script_path is not None:
        script_path.write_text(script)
        argv = [sys.executable, str(script_path)]
    else:
        argv = [sys.executable, "-c", script]
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        check=True,
    )
    return result.stdout.split()


def test_dotenv_values_reach_constants_when_importing_package():
    assert _run_constants_script(
        _STUBBED_SCRIPT.format(module="mcpscanner")
    ) == ["123456", "321"]


def test_dotenv_values_reach_constants_when_importing_cli():
    assert _run_constants_script(
        _STUBBED_SCRIPT.format(module="mcpscanner.cli")
    ) == ["123456", "321"]


def test_dotenv_in_working_directory_reaches_constants(tmp_path):
    """A real .env in the working directory, outside the package's parents."""
    project = tmp_path / "project"
    project.mkdir()
    (project / ".env").write_text(
        "MCP_SCANNER_ALIGNMENT_MAX_PROMPT_CHARS=123456\n"
        "MCP_SCANNER_LLM_TIMEOUT=321\n"
    )
    assert _run_constants_script(
        _REAL_SCRIPT, cwd=project, script_path=tmp_path / "run_scanner.py"
    ) == ["123456", "321"]
