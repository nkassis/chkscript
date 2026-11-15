"""The footprint summary: computed from findings, never by the model, and a
negative is stated only when the scan can back it."""

from __future__ import annotations

import pytest

from chkscript import footprint
from chkscript.models import Finding, Group, Location, Severity
from chkscript.preprocess import preprocess
from chkscript.static import StaticResult, run_static, shfmt
from tests.conftest import require_tool


def _finding(rule_id: str, group: Group | None = None, line: int = 3) -> Finding:
    unsafe = group is None
    return Finding(
        severity=Severity.UNSAFE if unsafe else Severity.WARNING,
        category="unsafe" if unsafe else "capability",
        description=rule_id,
        source="shfmt",
        rule_id=rule_id,
        line=line,
        group=group,
    )


def test_root_and_persistence_from_groups() -> None:
    result = footprint.compute(
        [
            _finding("runs-as-root", "root"),
            _finding("persistence-append", "persistence"),
        ],
        ["github.com"],
        coverage_full=True,
    )
    assert result.privilege == "root"
    assert result.persistence is True
    assert result.absent == ["system-write", "trust"]
    assert result.coverage == "full"


def test_backed_negatives() -> None:
    result = footprint.compute([], [], coverage_full=True)
    assert (result.privilege, result.persistence) == ("user", False)
    assert result.absent == ["persistence", "system-write", "trust"]


def test_reduced_coverage_states_no_negative() -> None:
    result = footprint.compute([], [], coverage_full=False)
    assert (result.privilege, result.persistence, result.absent) == (None, None, None)
    assert result.coverage == "reduced"


@pytest.mark.parametrize(
    "rule_id", ["eval-dynamic", "eval-remote", "curl-pipe-shell", "decode-to-shell"]
)
def test_unresolved_code_states_no_negative(rule_id: str) -> None:
    group: Group | None = "other" if rule_id == "eval-dynamic" else None
    result = footprint.compute([_finding(rule_id, group, 42)], [], coverage_full=True)
    assert result.unresolved_at == [Location(line=42)]
    assert (result.privilege, result.persistence, result.absent) == (None, None, None)


def test_a_positive_is_kept_when_negatives_cannot_be_backed() -> None:
    findings = [_finding("runs-as-root", "root"), _finding("eval-dynamic", "other")]
    result = footprint.compute(findings, [], coverage_full=False)
    assert result.privilege == "root"
    assert result.persistence is None


def test_a_raised_capability_still_counts() -> None:
    raised = _finding("persistence-append", "persistence").model_copy(
        update={"severity": Severity.UNSAFE, "category": "unsafe", "source": "llm"}
    )
    assert footprint.compute([raised], [], coverage_full=True).persistence is True


def test_hosts_are_distinct_sorted_and_unresolved_last() -> None:
    hosts = ["github.com", "(unresolved)", "get.k3s.io", "github.com"]
    result = footprint.compute([], hosts, coverage_full=True)
    assert result.network_hosts == ["get.k3s.io", "github.com", "(unresolved)"]


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://github.com/k3d-io/k3d/releases", "github.com"),
        ("https://User@Get.K3s.io:443/x", "get.k3s.io"),
        ("example.com/install.sh", "example.com"),
        ("http://localhost:8080/x", "localhost"),
        ("https://$HOST/x", footprint.UNRESOLVED_HOST),
        ("${BASE_URL}/x", footprint.UNRESOLVED_HOST),
        ("$URL", footprint.UNRESOLVED_HOST),
        ("https://github.com/$TAG/x", "github.com"),
    ],
)
def test_url_host(url: str, host: str) -> None:
    assert footprint.url_host(url) == host


def _static(
    body: str, monkeypatch: pytest.MonkeyPatch, engine: str = "shfmt"
) -> StaticResult:
    if engine == "shfmt":
        require_tool("shfmt")
    else:
        monkeypatch.setattr(shfmt, "check", lambda: "shfmt disabled for this test.")
    return run_static(preprocess(f"#!/bin/bash\n{body}\n".encode()))


def test_static_layer_records_download_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    body = (
        "curl -fsSL -o /tmp/a https://github.com/x/a\n"
        "wget -O /tmp/b https://get.example.com/b\n"
        'curl -fsSL "$MIRROR/c" -o /tmp/c'
    )
    result = _static(body, monkeypatch)
    assert result.hosts == ["get.example.com", "github.com", "(unresolved)"]
    assert result.coverage_full


def test_a_hinted_url_keeps_an_unresolved_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = ': "${URL:=https://get.example.com/i}"\ncurl -fsSL -o /tmp/i "$URL"'
    assert _static(body, monkeypatch).hosts == ["get.example.com", "(unresolved)"]


def test_regex_fallback_reduces_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _static(
        "curl -fsSL -o /tmp/a https://github.com/x/a", monkeypatch, "regex"
    )
    assert not result.coverage_full
    assert result.hosts == ["github.com"]


def test_unparseable_embedded_code_reduces_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not _static("bash -c 'if then (( x'", monkeypatch).coverage_full
