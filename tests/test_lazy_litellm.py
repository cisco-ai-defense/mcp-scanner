# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Guards for the deferred ``litellm`` import.

``litellm`` pulls in ~1700 extra modules, so importing ``mcpscanner`` must
not drag it in: every subcommand (and ``--help``) pays that cost otherwise.

The import-graph assertions run in a **subprocess** on purpose. Once any
test in this session touches an LLM analyzer, ``litellm`` is in the parent
process's ``sys.modules`` for good, so an in-process check would pass
whether or not the production import path is lazy.
"""

import asyncio
import subprocess
import sys
import types
from unittest.mock import AsyncMock, patch

import pytest

from mcpscanner.utils.lazy_litellm import (
    acompletion,
    is_litellm_available,
    litellm_import_error,
)


def _import_probe(module: str) -> subprocess.CompletedProcess:
    """Import ``module`` in a clean interpreter and report litellm's presence."""
    return subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import importlib, sys;"
                f"importlib.import_module({module!r});"
                "print('litellm' in sys.modules)"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "module",
    [
        "mcpscanner",
        "mcpscanner.cli",
        "mcpscanner.core.analyzers.llm_analyzer",
        "mcpscanner.core.analyzers.meta_analyzer",
        "mcpscanner.core.analyzers.readiness.llm_judge",
        "mcpscanner.core.analyzers.behavioral.alignment.alignment_llm_client",
    ],
)
def test_importing_module_does_not_import_litellm(module: str) -> None:
    """Importing any analyzer entry point must not pull in ``litellm``."""
    proc = _import_probe(module)
    assert proc.returncode == 0, f"import of {module} failed:\n{proc.stderr}"
    assert proc.stdout.strip() == "False", (
        f"importing {module} eagerly imported litellm; keep the import inside "
        f"mcpscanner.utils.lazy_litellm.acompletion.\nstderr:\n{proc.stderr}"
    )


def test_acompletion_is_a_coroutine_function() -> None:
    """``acompletion`` must stay ``async def``.

    ``unittest.mock.patch`` picks its replacement class from
    ``iscoroutinefunction``: a coroutine function becomes an ``AsyncMock``,
    anything else a ``MagicMock`` whose return value cannot be awaited. The
    suite patches these names in bare form and awaits the result, so a plain
    ``def`` here would break those tests.
    """
    assert asyncio.iscoroutinefunction(acompletion)


def test_acompletion_forwards_arguments_and_result() -> None:
    """The wrapper is a passthrough: args in, litellm's return value out.

    A stub module is injected into ``sys.modules`` rather than patching
    ``importlib.import_module`` itself: that function is used by the import
    system and by ``asyncio``, so replacing it globally breaks unrelated
    machinery mid-test.
    """
    sentinel = object()
    fake = AsyncMock(return_value=sentinel)

    stub = types.ModuleType("litellm")
    stub.acompletion = fake  # type: ignore[attr-defined]

    with patch.dict(sys.modules, {"litellm": stub}):
        result = asyncio.run(acompletion(model="gpt-4o", messages=[], api_key="k"))

    fake.assert_awaited_once_with(model="gpt-4o", messages=[], api_key="k")
    assert result is sentinel


def test_availability_probe_does_not_import_litellm() -> None:
    """``is_litellm_available`` uses ``find_spec``, so it must not execute litellm."""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys;"
                "from mcpscanner.utils.lazy_litellm import is_litellm_available;"
                "avail = is_litellm_available();"
                "print(avail, 'litellm' in sys.modules)"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    available, imported = proc.stdout.split()
    assert available == "True", "litellm is a project dependency; expected available"
    assert imported == "False", "availability probe must not import litellm"


def test_import_error_reason_is_none_when_available() -> None:
    """With litellm installed there is no unavailability reason to report."""
    assert is_litellm_available() is True
    assert litellm_import_error() is None
