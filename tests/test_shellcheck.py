from __future__ import annotations

import json

import pytest

from chkscript.models import Severity
from chkscript.preprocess import preprocess
from chkscript.static import shellcheck
from tests.conftest import require_tool

# Recorded from `shellcheck -f json -` (0.11.0), trimmed to the fields we read.
RECORDED = json.dumps(
    [
        {
            "file": "-",
            "line": 2,
            "column": 6,
            "level": "info",
            "code": 2086,
            "message": "Double quote to prevent globbing and word splitting.",
        },
        {
            "file": "-",
            "line": 3,
            "column": 1,
            "level": "error",
            "code": 2045,
            "message": "Iterating over ls output is fragile. Use globs.",
        },
        {
            "file": "-",
            "line": 4,
            "column": 3,
            "level": "warning",
            "code": 1091,
            "message": "Not following: ./env was not specified as input.",
        },
    ]
)

BUNDLE = preprocess(b"#!/bin/bash\necho $x\nfor f in $(ls); do :; done\n. ./env\n")


def test_every_finding_is_a_warning_with_sc_code_and_line() -> None:
    findings = shellcheck.parse_output(RECORDED, BUNDLE)
    assert [(f.rule_id, f.line) for f in findings] == [("SC2086", 2), ("SC2045", 3)]
    assert all(f.severity == Severity.WARNING for f in findings)
    assert all(f.source == "shellcheck" for f in findings)
    assert findings[0].snippet == "echo $x"


def test_error_level_is_still_only_a_warning() -> None:
    findings = shellcheck.parse_output(RECORDED, BUNDLE)
    assert findings[1].severity == Severity.WARNING


def test_suppressed_codes_dropped() -> None:
    ids = {f.rule_id for f in shellcheck.parse_output(RECORDED, BUNDLE)}
    assert not ids & shellcheck.SUPPRESSED


def test_unreadable_output_raises() -> None:
    with pytest.raises(shellcheck.ShellcheckError):
        shellcheck.parse_output("not json", BUNDLE)


def test_available_reflects_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shellcheck.shutil, "which", lambda _name: None)
    assert shellcheck.available() is False


def test_real_shellcheck() -> None:
    require_tool("shellcheck")
    findings = shellcheck.run(BUNDLE)
    assert "SC2086" in {f.rule_id for f in findings}
