"""shfmt adapter: version check, tree validation, parse failures."""

from __future__ import annotations

import json
import subprocess

import pytest
from pytest_mock import MockerFixture

from chkscript.static import shfmt
from tests.conftest import require_tool


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    shfmt._version.cache_clear()
    shfmt._parse_cached.cache_clear()


def _completed(stdout: str = "", stderr: str = "", code: int = 0) -> object:
    return subprocess.CompletedProcess([], code, stdout=stdout, stderr=stderr)


def test_missing_shfmt_is_a_notice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shfmt.shutil, "which", lambda _: None)
    notice = shfmt.check()
    assert notice is not None and "not found" in notice


def test_old_shfmt_is_a_notice(
    monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.setattr(shfmt.shutil, "which", lambda _: "/usr/bin/shfmt")
    mocker.patch.object(shfmt.subprocess, "run", return_value=_completed("v3.5.0\n"))
    assert shfmt.check() == "shfmt v3.5.0 is older than v3.14.0; using the regex rules."


def test_current_shfmt_passes_the_check(
    monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.setattr(shfmt.shutil, "which", lambda _: "/usr/bin/shfmt")
    run = mocker.patch.object(
        shfmt.subprocess, "run", return_value=_completed("v3.14.1\n")
    )
    assert shfmt.check() is None
    assert shfmt.check() is None
    assert run.call_count == 1  # the version is read once per binary


def test_unreadable_version_is_a_notice(
    monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.setattr(shfmt.shutil, "which", lambda _: "/usr/bin/shfmt")
    mocker.patch.object(shfmt.subprocess, "run", return_value=_completed("(devel)\n"))
    notice = shfmt.check()
    assert notice is not None and "version" in notice


def test_parse_error_keeps_the_line() -> None:
    error = shfmt.parse_error(
        "<standard input>:4:3: reached EOF without matching ( with )\n"
    )
    assert error.line == 4
    assert "reached EOF" in str(error)


def test_parse_error_without_position() -> None:
    assert shfmt.parse_error("panic: something\n").line is None


@pytest.mark.parametrize(
    "output",
    ["not json", "[]", json.dumps({"Type": "Stmt"})],
    ids=["invalid-json", "not-an-object", "not-a-file"],
)
def test_unexpected_output_is_an_error(output: str) -> None:
    with pytest.raises(shfmt.ShfmtError):
        shfmt.decode(output)


def test_integer_operators_are_rejected() -> None:
    # Before v3.14.0, --to-json wrote operators as integers.
    tree = {"Type": "File", "Stmts": [{"Cmd": {"Type": "BinaryCmd", "Op": 12}}]}
    with pytest.raises(shfmt.ShfmtError, match="integers"):
        shfmt.decode(json.dumps(tree))


def test_timeout_is_an_error(mocker: MockerFixture) -> None:
    mocker.patch.object(
        shfmt.subprocess, "run", side_effect=subprocess.TimeoutExpired("shfmt", 60)
    )
    with pytest.raises(shfmt.ShfmtError, match="timed out"):
        shfmt.parse("echo hi\n")


def test_parses_as_bash_whatever_the_shebang() -> None:
    require_tool("shfmt")
    # `[[ ]]` and arrays are not POSIX; a `#!/bin/sh` shebang must not matter.
    tree = shfmt.parse('#!/bin/sh\nA=(x y)\n[[ -n "$A" ]] && echo "${A[@]}"\n')
    assert tree["Type"] == "File"
    assert len(tree["Stmts"]) == 2


def test_operators_are_strings() -> None:
    require_tool("shfmt")
    tree = shfmt.parse("curl x | sh >> log\n")
    cmd = tree["Stmts"][0]["Cmd"]
    assert cmd["Op"] == "|"
    assert cmd["Y"]["Redirs"][0]["Op"] == ">>"


def test_real_parse_failure_reports_its_line() -> None:
    require_tool("shfmt")
    with pytest.raises(shfmt.ShfmtError) as exc:
        shfmt.parse("echo ok\nif true; then\n")
    assert exc.value.line is not None
