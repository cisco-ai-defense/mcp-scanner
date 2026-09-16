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

"""Logging that a scan is trustworthy enough to rely on.

Two concerns live here. The first is arity: ``logger.info("%s", a, b)``
raises only when that level is enabled, so a broken debug line ships
green and fails the first time someone turns debug on to diagnose an
incident. The check below reads every call statically instead.

The second is silence. Several analyzers report "nothing found" both
when a target is clean and when the check itself crashed. Those cases
must not look alike in the log, and the tests here fail if they do.
"""

import ast
import contextlib
import logging
import pathlib

import pytest


@contextlib.contextmanager
def capturing(logger, caplog, level):
    """Let ``caplog`` see records from one mcpscanner logger.

    ``get_logger`` sets ``propagate = False`` so scan output cannot leak
    into a host application's root handler. caplog installs its handler
    on exactly that root logger, so it sees nothing unless propagation is
    restored for the duration of the assertion.
    """
    previous = logger.propagate
    logger.propagate = True
    try:
        with caplog.at_level(level, logger=logger.name):
            yield
    finally:
        logger.propagate = previous


PACKAGE_ROOT = pathlib.Path(__file__).resolve().parent.parent / "mcpscanner"
LOG_LEVELS = {"debug", "info", "warning", "error", "critical", "exception"}


def _iter_log_calls():
    """Every ``logger.<level>(...)`` call in the package, with its location."""
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in LOG_LEVELS
                and "log" in ast.unparse(node.func.value).lower()
            ):
                yield path, node


def _placeholder_count(fmt: str) -> int:
    """Number of %-substitutions the runtime will try to fill."""
    count, i = 0, 0
    while i < len(fmt) - 1:
        if fmt[i] == "%":
            if fmt[i + 1] == "%":
                i += 2
                continue
            count += 1
        i += 1
    return count


class TestLogCallArity:
    """A log line must not raise when its level is switched on."""

    def test_every_literal_format_matches_its_argument_count(self):
        mismatches = []
        for path, node in _iter_log_calls():
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            fmt = node.args[0].value
            if not isinstance(fmt, str):
                continue
            supplied = len(node.args) - 1
            # *args forwarding makes the count unknowable statically.
            if any(isinstance(a, ast.Starred) for a in node.args):
                continue
            expected = _placeholder_count(fmt)
            if expected != supplied:
                rel = path.relative_to(PACKAGE_ROOT.parent)
                mismatches.append(
                    f"{rel}:{node.lineno} wants {expected} arg(s), got {supplied}: {fmt!r}"
                )
        assert not mismatches, "log calls that raise when enabled:\n" + "\n".join(
            mismatches
        )

    def test_no_fstring_log_messages(self):
        """f-strings render even when the level is off, and defeat grouping."""
        offenders = []
        for path, node in _iter_log_calls():
            if node.args and isinstance(node.args[0], ast.JoinedStr):
                if any(isinstance(v, ast.FormattedValue) for v in node.args[0].values):
                    rel = path.relative_to(PACKAGE_ROOT.parent)
                    offenders.append(f"{rel}:{node.lineno}")
        assert (
            not offenders
        ), "use lazy %-style args instead of f-strings:\n" + "\n".join(offenders)


class TestAbortedChecksAreNotSilent:
    """A check that crashed must not read as a check that passed."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "check,check_id",
        [
            ("_check_replay", "MCPS-004"),
            ("_check_spoofed_identity", "MCPS-007"),
            ("_check_rate_limiting", "MCPS-009"),
        ],
    )
    async def test_protocol_check_logs_when_it_cannot_complete(
        self, check, check_id, caplog
    ):
        from mcpscanner.core.analyzers.protocol_analyzer import ProtocolAnalyzer

        class ExplodingClient:
            async def post(self, *args, **kwargs):
                raise ConnectionError("connection reset")

        analyzer = ProtocolAnalyzer()
        with capturing(analyzer.logger, caplog, logging.WARNING):
            findings = await getattr(analyzer, check)(
                ExplodingClient(), "http://target.invalid"
            )

        # The empty result is the pre-existing contract; the log is what
        # stops it from being mistaken for a verified-clean server.
        assert findings == []
        text = caplog.text
        assert check_id in text
        assert "ConnectionError" in text
        assert "not actually verified" in text

    @pytest.mark.asyncio
    async def test_failing_analyzer_is_named_in_the_log(self, caplog):
        from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer

        class BrokenAnalyzer:
            name = "exploding_analyzer"

            async def analyze(self, content, context):
                raise RuntimeError("rule compilation failed")

        aggregate = StaticAnalyzer.__new__(StaticAnalyzer)
        aggregate.analyzers = [BrokenAnalyzer()]

        from mcpscanner.core.analyzers import static_analyzer as sa_module

        with capturing(sa_module.logger, caplog, logging.ERROR):
            findings = await aggregate._analyze_content("content", {})

        assert findings == []
        assert "exploding_analyzer" in caplog.text
        assert "RuntimeError" in caplog.text


class TestLibraryCodeDoesNotPrint:
    """Scan output belongs on the log, not on a caller's stdout."""

    ALLOWED = {
        # Interactive OAuth: the user must see the URL to paste it back.
        "mcpscanner/core/auth.py",
        # Deliberate passthrough of container stderr under --verbose.
        "mcpscanner/core/pypi_scanner.py",
        "mcpscanner/core/npm_scanner.py",
    }

    def test_no_stray_prints_outside_cli_and_docker(self):
        offenders = []
        for path in sorted(PACKAGE_ROOT.rglob("*.py")):
            rel = path.relative_to(PACKAGE_ROOT.parent).as_posix()
            if rel.startswith(("mcpscanner/cli/", "mcpscanner/docker/")):
                continue
            if rel in self.ALLOWED:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "print"
                ):
                    offenders.append(f"{rel}:{node.lineno}")
        assert not offenders, "library code should log, not print:\n" + "\n".join(
            offenders
        )
