import os
import time
from pathlib import Path

import pytest

from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer


@pytest.mark.asyncio
async def test_yara_compile_cached_across_instances(tmp_path, monkeypatch):
    # Create a temporary rules directory with a simple rule
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "test_rule.yara"
    rule_file.write_text(
        "rule TEST_RULE { condition: true }",
        encoding="utf-8",
    )

    compile_calls = {"count": 0}

    def fake_compile(**kwargs):
        compile_calls["count"] += 1
        # Return any object; analyzer doesn't use the returned type here
        class DummyRules:
            def match(self, data=None):
                return []

        return DummyRules()

    monkeypatch.setattr(
        "mcpscanner.core.analyzers.yara_analyzer.yara.compile", fake_compile
    )

    # First instance compiles rules
    _ = YaraAnalyzer(config=None, rules_dir=str(rules_dir))
    # Second instance should reuse cache, no compile
    _ = YaraAnalyzer(config=None, rules_dir=str(rules_dir))

    assert compile_calls["count"] == 1

    # Touch the rule file to change mtime => invalidates cache key
    time.sleep(0.01)
    rule_file.write_text(
        "rule TEST_RULE { condition: true } // modified",
        encoding="utf-8",
    )

    _ = YaraAnalyzer(config=None, rules_dir=str(rules_dir))

    assert compile_calls["count"] == 2


