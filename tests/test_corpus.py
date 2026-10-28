"""Real-installer corpus: today's static verdicts, pinned in tests/corpus/expected.toml.

Each installer runs through the static layer under Semgrep and under the regex
fallback alone (shellcheck runs in both), and any difference from the agreed
verdict fails. No network: every script is a pinned copy.
"""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path
from typing import Any

import pytest

from chkscript.models import Severity
from chkscript.preprocess import preprocess
from chkscript.static import StaticResult, run_static, semgrep
from tests.conftest import require_tool

CORPUS = Path(__file__).parent / "corpus"
EXPECTED: dict[str, Any] = tomllib.loads((CORPUS / "expected.toml").read_text())
ENGINES = ("semgrep", "regex")
VERDICTS = {"true-positive", "noise"}


def _run(name: str, engine: str, monkeypatch: pytest.MonkeyPatch) -> StaticResult:
    require_tool("shellcheck")
    if engine == "semgrep":
        require_tool("semgrep")
    else:
        monkeypatch.setattr(semgrep, "available", lambda: False)
    return run_static(preprocess((CORPUS / name / "install.sh").read_bytes()))


def _expected_findings(name: str, engine: str) -> list[dict[str, Any]]:
    return [f for f in EXPECTED[name]["finding"] if engine in f.get("engines", ENGINES)]


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_corpus_verdict(
    name: str, engine: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run(name, engine, monkeypatch)
    expected = _expected_findings(name, engine)

    actual_max = max((f.severity for f in result.findings), default=Severity.SAFE)
    assert actual_max.name.lower() == EXPECTED[name]["max_severity"]

    assert {f.rule_id for f in result.findings} == {e["rule"] for e in expected}

    pinned: dict[str, list[int]] = {}
    for entry in expected:
        if "lines" in entry:
            pinned.setdefault(entry["rule"], []).extend(entry["lines"])
    for rule, lines in pinned.items():
        actual = sorted(f.line for f in result.findings if f.rule_id == rule)
        assert actual == sorted(lines), rule


def test_every_installer_has_an_expected_entry() -> None:
    scripts = {p.parent.name for p in CORPUS.glob("*/install.sh")}
    assert scripts == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_expected_entries_are_well_formed(name: str) -> None:
    table = EXPECTED[name]
    assert table["max_severity"] in {"safe", "warning", "unsafe"}
    for entry in table["finding"]:
        assert entry["verdict"] in VERDICTS, entry
        assert entry["note"].strip(), entry
        assert "\n" not in entry["note"], entry
        assert set(entry.get("engines", ENGINES)) <= set(ENGINES), entry


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_source_records_pinned_hash_and_license(name: str) -> None:
    fields = dict(
        line.split(": ", 1)
        for line in (CORPUS / name / "SOURCE").read_text().splitlines()
    )
    assert {"url", "fetched", "sha256", "license", "license_url"} <= set(fields)
    digest = hashlib.sha256((CORPUS / name / "install.sh").read_bytes()).hexdigest()
    assert fields["sha256"] == digest
    assert (CORPUS / name / "LICENSE").is_file()
