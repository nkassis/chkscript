"""Golden suite: each fixture's max severity and unsafe rule ids, per engine.

"semgrep" is the normal static layer. "regex" hides Semgrep so the regex
fallback stands in for it; shellcheck runs in both, since the warning tier is
independent of which engine provides the unsafe tier.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from chkscript.models import Severity
from chkscript.preprocess import preprocess
from chkscript.static import StaticResult, run_static, semgrep, shellcheck
from tests.conftest import require_tool

ROOT = Path(__file__).parent

# fixture path -> (expected max severity, expected unsafe rule ids)
GOLDEN: dict[str, tuple[Severity, set[str]]] = {
    "fixtures/safe.sh": (Severity.SAFE, set()),
    "fixtures/warnings_only.sh": (Severity.WARNING, set()),
    "fixtures/curl_pipe_sh.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
    "fixtures/eval_variable.sh": (Severity.UNSAFE, {"eval-dynamic"}),
    "fixtures/base64_to_sh.sh": (Severity.UNSAFE, {"decode-to-shell"}),
    "fixtures/injection_comment.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
    "fixtures/unparseable.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
    "fixtures/http_download.sh": (Severity.UNSAFE, {"http-download"}),
    "fixtures/binary_no_checksum.sh": (Severity.UNSAFE, {"unverified-download"}),
    "fixtures/binary_with_checksum.sh": (Severity.SAFE, set()),
    # The k3d installers moved to tests/corpus/ and are pinned by test_corpus.py.
}


def _run(path: str, engine: str, monkeypatch: pytest.MonkeyPatch) -> StaticResult:
    require_tool("shellcheck")
    if engine == "semgrep":
        require_tool("semgrep")
    else:
        monkeypatch.setattr(semgrep, "available", lambda: False)
    return run_static(preprocess((ROOT / path).read_bytes()))


@pytest.mark.parametrize("engine", ["semgrep", "regex"])
@pytest.mark.parametrize("path", sorted(GOLDEN))
def test_golden(path: str, engine: str, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run(path, engine, monkeypatch)
    expected_severity, expected_ids = GOLDEN[path]

    severities = [f.severity for f in result.findings]
    assert max(severities, default=Severity.SAFE) == expected_severity
    unsafe_ids = {f.rule_id for f in result.findings if f.severity == Severity.UNSAFE}
    assert unsafe_ids == expected_ids


def test_unparseable_reports_parse_warning_and_regex_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run("fixtures/unparseable.sh", "semgrep", monkeypatch)

    parse = [f for f in result.findings if f.rule_id == semgrep.PARSE_ERROR_RULE]
    assert len(parse) == 1
    assert parse[0].severity == Severity.WARNING
    assert parse[0].source == "chkscript"
    assert parse[0].description == semgrep.PARSE_ERROR_MESSAGE

    pipe = [f for f in result.findings if f.rule_id == "curl-pipe-shell"]
    assert len(pipe) == 1
    assert "regex" in pipe[0].merged_from
    assert result.tools == ["shellcheck", "semgrep", "regex"]


def test_injection_comment_does_not_suppress_static_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run("fixtures/injection_comment.sh", "semgrep", monkeypatch)
    pipe = [f for f in result.findings if f.rule_id == "curl-pipe-shell"]
    assert [f.severity for f in pipe] == [Severity.UNSAFE]
    assert pipe[0].line == 6


def test_no_tools_still_reports_with_regex_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(semgrep, "available", lambda: False)
    monkeypatch.setattr(shellcheck, "available", lambda: False)
    result = run_static(preprocess((ROOT / "fixtures/curl_pipe_sh.sh").read_bytes()))

    assert result.tools == ["regex"]
    assert any("Only the regex rules ran" in n for n in result.notices)
    assert {f.rule_id for f in result.findings} == {"curl-pipe-shell"}
