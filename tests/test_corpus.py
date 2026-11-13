"""Real-installer corpus: today's static verdicts, pinned in tests/corpus/expected.toml.

Each installer runs through the static layer under the shfmt engine and under
the regex fallback alone (shellcheck runs in both), and any difference from the
agreed verdict fails. No network: every script is a pinned copy.
"""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path
from typing import Any

import pytest

from chkscript.models import ENTRY_FILE, Severity
from chkscript.preprocess import preprocess
from chkscript.static import StaticResult, run_static, shfmt
from tests.conftest import require_tool

CORPUS = Path(__file__).parent / "corpus"
EXPECTED: dict[str, Any] = tomllib.loads((CORPUS / "expected.toml").read_text())
ENGINES = ("shfmt", "regex")
VERDICTS = {"true-positive", "noise"}


def _run(name: str, engine: str, monkeypatch: pytest.MonkeyPatch) -> StaticResult:
    require_tool("shellcheck")
    if engine == "shfmt":
        require_tool("shfmt")
    else:
        monkeypatch.setattr(shfmt, "check", lambda: "shfmt disabled for this test.")
    return run_static(preprocess((CORPUS / name / "install.sh").read_bytes()))


def _expected_findings(name: str, engine: str) -> list[dict[str, Any]]:
    return [f for f in EXPECTED[name]["finding"] if engine in f.get("engines", ENGINES)]


def _key(rule: str, file: str) -> tuple[str, str]:
    # shellcheck codes are pinned by id alone, wherever they fire.
    return (rule, "" if rule.startswith("SC") else file)


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_corpus_verdict(
    name: str, engine: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run(name, engine, monkeypatch)
    expected = _expected_findings(name, engine)
    table = EXPECTED[name]

    actual_max = max((f.severity for f in result.findings), default=Severity.SAFE)
    wanted_max = table.get(f"{engine}_max_severity", table["max_severity"])
    assert actual_max.name.lower() == wanted_max

    actual = {_key(f.rule_id or "", f.file) for f in result.findings}
    wanted = {_key(e["rule"], e.get("file", ENTRY_FILE)) for e in expected}
    assert actual == wanted

    pinned: dict[tuple[str, str], list[int]] = {}
    for entry in expected:
        if "lines" in entry:
            key = (entry["rule"], entry.get("file", ENTRY_FILE))
            pinned.setdefault(key, []).extend(entry["lines"])
    for (rule, file), lines in pinned.items():
        found = sorted(
            f.line or 0 for f in result.findings if f.rule_id == rule and f.file == file
        )
        assert found == sorted(lines), (rule, file)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_every_installer_parses(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run(name, "shfmt", monkeypatch)
    assert "regex" not in result.tools
    assert not any(f.rule_id == shfmt.PARSE_FAILURE_RULE for f in result.findings)


def test_every_installer_has_an_expected_entry() -> None:
    scripts = {p.parent.name for p in CORPUS.glob("*/install.sh")}
    assert scripts == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_expected_entries_are_well_formed(name: str) -> None:
    table = EXPECTED[name]
    severities = {"safe", "warning", "unsafe"}
    assert table["max_severity"] in severities
    for engine in ENGINES:
        assert table.get(f"{engine}_max_severity", "safe") in severities
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
