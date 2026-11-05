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

# MCPScannerConstants reads its os.getenv() defaults once, when the class is
# defined. Run the import in a fresh interpreter, with load_dotenv stubbed to
# set a value the way a .env file would, and check the constants see it.
_SCRIPT = textwrap.dedent(
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


def _constants_after_import(module: str) -> list[str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("MCP_SCANNER_ALIGNMENT_MAX_PROMPT_CHARS", "MCP_SCANNER_LLM_TIMEOUT")
    }
    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT.format(module=module)],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return result.stdout.split()


def test_dotenv_values_reach_constants_when_importing_package():
    assert _constants_after_import("mcpscanner") == ["123456", "321"]


def test_dotenv_values_reach_constants_when_importing_cli():
    assert _constants_after_import("mcpscanner.cli") == ["123456", "321"]
