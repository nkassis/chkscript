from __future__ import annotations

import itertools

import pytest

from chkscript.models import Finding, Severity, Source
from chkscript.static.merge import merge


def _finding(
    severity: Severity,
    source: Source,
    rule_id: str | None = "curl-pipe-shell",
    line: int | None = 4,
    description: str = "d",
) -> Finding:
    return Finding(
        severity=severity,
        source=source,
        rule_id=rule_id,
        line=line,
        description=description,
    )


def test_same_key_merges_and_lists_all_sources() -> None:
    merged = merge(
        [
            _finding(Severity.UNSAFE, "semgrep"),
            _finding(Severity.UNSAFE, "regex"),
        ]
    )
    assert len(merged) == 1
    assert merged[0].merged_from == ["semgrep", "regex"]


def test_single_finding_lists_its_own_source() -> None:
    assert merge([_finding(Severity.WARNING, "shellcheck")])[0].merged_from == [
        "shellcheck"
    ]


def test_different_line_or_rule_or_file_not_merged() -> None:
    base = _finding(Severity.UNSAFE, "semgrep")
    others = [
        base.model_copy(update={"line": 5}),
        base.model_copy(update={"rule_id": "http-download"}),
        base.model_copy(update={"file": "https://x.example/stage2.sh"}),
    ]
    assert len(merge([base, *others])) == 4


def test_findings_without_rule_id_never_merge() -> None:
    llm = _finding(Severity.WARNING, "llm", rule_id=None, line=None)
    assert len(merge([llm, llm])) == 2


def test_merge_keeps_description_of_most_severe() -> None:
    merged = merge(
        [
            _finding(Severity.WARNING, "llm", description="minor"),
            _finding(Severity.UNSAFE, "semgrep", description="major"),
        ]
    )
    assert merged[0].severity == Severity.UNSAFE
    assert merged[0].description == "major"
    assert merged[0].merged_from == ["llm", "semgrep"]


SEVERITIES = [Severity.WARNING, Severity.UNSAFE]
SOURCES: list[Source] = ["semgrep", "regex", "llm"]


@pytest.mark.parametrize(
    "combo",
    list(itertools.product(itertools.product(SEVERITIES, SOURCES), repeat=3)),
)
def test_merge_never_lowers_severity(
    combo: tuple[tuple[Severity, Source], ...],
) -> None:
    """For every ordering and mix of inputs on one key, the merged severity is
    the maximum input severity, so merging can only raise a finding."""
    findings = [_finding(severity, source) for severity, source in combo]
    merged = merge(findings)
    assert len(merged) == 1
    assert merged[0].severity == max(f.severity for f in findings)
    for original in findings:
        assert merged[0].severity >= original.severity
