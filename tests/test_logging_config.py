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

"""Tests for logging configuration and set_log_level."""

import logging

import pytest

from mcpscanner.utils.logging_config import (
    get_logger,
    set_log_level,
    set_verbose_logging,
    setup_logger,
)


def _cleanup_loggers(*names: str):
    """Remove handlers and reset levels on test loggers."""
    for name in names:
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.setLevel(logging.NOTSET)
        lg.propagate = True


class TestSetLogLevel:
    """Tests for the set_log_level function."""

    def setup_method(self):
        self.child_names = [
            "mcpscanner.test_child_a",
            "mcpscanner.test_child_b",
            "mcpscanner.test_child_a.deep",
        ]
        for name in self.child_names:
            _cleanup_loggers(name)
        _cleanup_loggers("mcpscanner")

    def teardown_method(self):
        for name in self.child_names:
            _cleanup_loggers(name)

    def test_set_log_level_affects_root_mcpscanner_logger(self):
        root = logging.getLogger("mcpscanner")
        set_log_level(logging.ERROR)
        assert root.level == logging.ERROR

    def test_set_log_level_affects_existing_child_loggers(self):
        child_a = get_logger("mcpscanner.test_child_a")
        child_b = get_logger("mcpscanner.test_child_b")
        assert child_a.level == logging.INFO
        assert child_b.level == logging.INFO

        set_log_level(logging.ERROR)

        assert child_a.level == logging.ERROR
        assert child_b.level == logging.ERROR

    def test_set_log_level_updates_handler_levels(self):
        child = get_logger("mcpscanner.test_child_a")
        assert child.handlers
        for h in child.handlers:
            assert h.level == logging.INFO

        set_log_level(logging.CRITICAL)

        for h in child.handlers:
            assert h.level == logging.CRITICAL

    def test_set_log_level_suppresses_info_messages(self, capfd):
        child = get_logger("mcpscanner.test_child_a")
        set_log_level(logging.ERROR)

        child.info("this should be suppressed")
        child.warning("this should also be suppressed")
        child.error("this should appear")

        captured = capfd.readouterr()
        assert "this should be suppressed" not in captured.out
        assert "this should also be suppressed" not in captured.out
        assert "this should appear" in captured.out

    def test_set_log_level_to_debug_shows_all(self, capfd):
        child = get_logger("mcpscanner.test_child_b")
        set_log_level(logging.DEBUG)

        child.debug("debug message")
        child.info("info message")

        captured = capfd.readouterr()
        assert "debug message" in captured.out
        assert "info message" in captured.out

    def test_set_log_level_deep_child(self):
        deep = get_logger("mcpscanner.test_child_a.deep")
        set_log_level(logging.WARNING)
        assert deep.level == logging.WARNING

    def test_set_log_level_does_not_affect_non_mcpscanner(self):
        other = logging.getLogger("some_other_library")
        original_level = other.level
        set_log_level(logging.CRITICAL)
        assert other.level == original_level

    def test_set_log_level_multiple_calls(self):
        child = get_logger("mcpscanner.test_child_a")

        set_log_level(logging.ERROR)
        assert child.level == logging.ERROR

        set_log_level(logging.DEBUG)
        assert child.level == logging.DEBUG

        set_log_level(logging.WARNING)
        assert child.level == logging.WARNING


class TestSetVerboseLogging:
    """Tests for set_verbose_logging (delegates to set_log_level)."""

    def setup_method(self):
        self.child_name = "mcpscanner.test_verbose"
        _cleanup_loggers(self.child_name, "mcpscanner")

    def teardown_method(self):
        _cleanup_loggers(self.child_name)

    def test_verbose_true_sets_debug(self):
        child = get_logger(self.child_name)
        set_verbose_logging(True)
        assert child.level == logging.DEBUG

    def test_verbose_false_sets_info(self):
        child = get_logger(self.child_name)
        set_verbose_logging(True)
        set_verbose_logging(False)
        assert child.level == logging.INFO


class TestPublicImports:
    """Verify set_log_level and set_verbose_logging are importable from top-level."""

    def test_import_from_mcpscanner(self):
        from mcpscanner import set_log_level as sl, set_verbose_logging as sv

        assert callable(sl)
        assert callable(sv)

    def test_import_from_utils(self):
        from mcpscanner.utils import set_log_level as sl, set_verbose_logging as sv

        assert callable(sl)
        assert callable(sv)
