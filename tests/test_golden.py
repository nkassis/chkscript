"""Golden suite: each fixture's max severity and unsafe rule ids, per engine,
and under the syntax tree its capability rule ids.

"shfmt" is the normal static layer. "regex" makes shfmt unusable so the regex
fallback stands in for it; shellcheck runs in both, since the warning tier is
independent of which engine provides the unsafe tier.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from chkscript.models import Severity
from chkscript.preprocess import preprocess
from chkscript.static import StaticResult, rules, run_static, shellcheck, shfmt
from tests.conftest import require_tool

ROOT = Path(__file__).parent

# fixture path -> (expected max severity, expected unsafe rule ids)
GOLDEN: dict[str, tuple[Severity, set[str]]] = {
    "fixtures/safe.sh": (Severity.SAFE, set()),
    "fixtures/warnings_only.sh": (Severity.WARNING, set()),
    "fixtures/curl_pipe_sh.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
    # eval of a local file's contents: a capability (eval-dynamic), not remote.
    "fixtures/eval_variable.sh": (Severity.WARNING, set()),
    "fixtures/base64_to_sh.sh": (Severity.UNSAFE, {"decode-to-shell"}),
    "fixtures/evasion_var_cmd.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
    "fixtures/injection_comment.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
    "fixtures/unparseable.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
    "fixtures/http_download.sh": (Severity.UNSAFE, {"http-download"}),
    # Integrity resting on TLS alone is a capability now (docs/spec.md).
    "fixtures/binary_no_checksum.sh": (Severity.WARNING, set()),
    # Verified, but it still installs to /usr/local/bin with sudo.
    "fixtures/binary_with_checksum.sh": (Severity.WARNING, set()),
    "fixtures/docker_group.sh": (Severity.WARNING, set()),
    "fixtures/apt_global_key.sh": (Severity.WARNING, set()),
    "fixtures/apt_signed_by.sh": (Severity.WARNING, set()),
    # The k3d installers moved to tests/corpus/ and are pinned by test_corpus.py.
}


# Where the fallback over-reports by design: `curl ... | sudo gpg` reads as a
# download piped to sudo, which may run a shell.
REGEX_GOLDEN: dict[str, tuple[Severity, set[str]]] = {
    "fixtures/apt_global_key.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
    "fixtures/apt_signed_by.sh": (Severity.UNSAFE, {"curl-pipe-shell"}),
}

# fixture path -> capability rule ids the syntax-tree engine reports.
CAPABILITIES: dict[str, set[str]] = {
    "fixtures/safe.sh": set(),
    "fixtures/eval_variable.sh": {"eval-dynamic"},
    "fixtures/binary_no_checksum.sh": {
        "unverified-download",
        "runs-as-root",
        "system-path-write",
    },
    "fixtures/binary_with_checksum.sh": {"runs-as-root", "system-path-write"},
    "fixtures/docker_group.sh": {"root-equivalent-group", "runs-as-root"},
    "fixtures/apt_global_key.sh": {"package-repo-added", "runs-as-root"},
    "fixtures/apt_signed_by.sh": {"package-repo-added", "runs-as-root"},
}


def _run(path: str, engine: str, monkeypatch: pytest.MonkeyPatch) -> StaticResult:
    require_tool("shellcheck")
    if engine == "shfmt":
        require_tool("shfmt")
    else:
        monkeypatch.setattr(shfmt, "check", lambda: "shfmt disabled for this test.")
    return run_static(preprocess((ROOT / path).read_bytes()))


@pytest.mark.parametrize("engine", ["shfmt", "regex"])
@pytest.mark.parametrize("path", sorted(GOLDEN))
def test_golden(path: str, engine: str, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run(path, engine, monkeypatch)
    expected_severity, expected_ids = GOLDEN[path]
    if engine == "regex":
        expected_severity, expected_ids = REGEX_GOLDEN.get(
            path, (expected_severity, expected_ids)
        )

    severities = [f.severity for f in result.findings]
    assert max(severities, default=Severity.SAFE) == expected_severity
    unsafe_ids = {f.rule_id for f in result.findings if f.severity == Severity.UNSAFE}
    assert unsafe_ids == expected_ids


@pytest.mark.parametrize("path", sorted(CAPABILITIES))
def test_golden_capabilities(path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run(path, "shfmt", monkeypatch)
    found = {f.rule_id for f in result.findings if f.category == "capability"}
    assert found == CAPABILITIES[path]


def test_docker_group_fires_on_docker_not_on_sudo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run("fixtures/docker_group.sh", "shfmt", monkeypatch)
    groups = [f for f in result.findings if f.rule_id == "root-equivalent-group"]
    assert [(f.line, f.subject, f.group) for f in groups] == [(6, "docker", "trust")]


@pytest.mark.parametrize(
    ("path", "scope"),
    [("fixtures/apt_global_key.sh", "global"), ("fixtures/apt_signed_by.sh", "scoped")],
)
def test_apt_repo_names_its_key_scope(
    path: str, scope: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run(path, "shfmt", monkeypatch)
    repos = [f for f in result.findings if f.rule_id == "package-repo-added"]
    assert repos
    assert all(
        f.description == rules.message("package-repo-added", scope) for f in repos
    )


def test_unparseable_reports_parse_warning_and_regex_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run("fixtures/unparseable.sh", "shfmt", monkeypatch)

    parse = [f for f in result.findings if f.rule_id == shfmt.PARSE_FAILURE_RULE]
    assert len(parse) == 1
    assert parse[0].severity == Severity.WARNING
    assert parse[0].source == "chkscript"
    assert parse[0].description == shfmt.PARSE_FAILURE_MESSAGE

    pipe = [f for f in result.findings if f.rule_id == "curl-pipe-shell"]
    assert len(pipe) == 1
    assert "regex" in pipe[0].merged_from
    assert result.tools == ["shellcheck", "shfmt", "regex"]


def test_injection_comment_does_not_suppress_static_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run("fixtures/injection_comment.sh", "shfmt", monkeypatch)
    pipe = [f for f in result.findings if f.rule_id == "curl-pipe-shell"]
    assert [f.severity for f in pipe] == [Severity.UNSAFE]
    assert pipe[0].line == 6


def test_no_tools_still_reports_with_regex_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shfmt, "check", lambda: "shfmt not found on PATH; x.")
    monkeypatch.setattr(shellcheck, "available", lambda: False)
    result = run_static(preprocess((ROOT / "fixtures/curl_pipe_sh.sh").read_bytes()))

    assert result.tools == ["regex"]
    assert any("Only the regex rules ran" in n for n in result.notices)
    assert {f.rule_id for f in result.findings} == {"curl-pipe-shell"}
