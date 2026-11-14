"""Fallback superset (spec, Testing, property 4).

For every corpus installer and every fixture, the regex fallback reports at
least the unsafe findings the syntax-tree engine reports: the same rule id on
the same line or a nearby one. Losing the parser may add findings, never remove
an unsafe one. A finding in a generated child file is compared at the parent
line its child line comes from, since the fallback sees the heredoc in place.
tests/test_rules.py runs the same check over every rule snippet.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from chkscript.models import ScriptBundle, Severity
from chkscript.preprocess import preprocess
from chkscript.static import engine, regex_rules
from tests.conftest import require_tool

ROOT = Path(__file__).parent
SCRIPTS = sorted(
    [*ROOT.glob("corpus/*/install.sh"), *ROOT.glob("fixtures/*.sh")],
    key=lambda p: str(p),
)
# "Nearby": the engine and the text can place one command a line or two apart
# (a continued line, a pipeline split after `|`).
NEARBY = 2
MAX_DEPTH = 3


def _tree_unsafe(
    bundle: ScriptBundle, offset: int = 0, depth: int = 0
) -> set[tuple[str, int]]:
    """(rule id, entry-file line) for every unsafe finding the engine reports,
    generated children included."""
    outcome = engine.scan(bundle)
    found = {
        (f.rule_id, (f.line or 0) + offset)
        for f in outcome.findings
        if f.severity == Severity.UNSAFE and f.rule_id is not None
    }
    if depth < MAX_DEPTH:
        for child in outcome.generated:
            child_bundle = preprocess(child.text.encode(), file=child.label)
            found |= _tree_unsafe(child_bundle, offset + child.body_line - 1, depth + 1)
    return found


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_regex_reports_every_unsafe_tree_finding(path: Path) -> None:
    require_tool("shfmt")
    bundle = preprocess(path.read_bytes())
    tree = _tree_unsafe(bundle)
    regex: dict[str, set[int]] = {}
    for finding in regex_rules.run(bundle):
        regex.setdefault(finding.rule_id or "", set()).add(finding.line or 0)
    missing = sorted(
        (rule, line)
        for rule, line in tree
        if not any(abs(line - other) <= NEARBY for other in regex.get(rule, ()))
    )
    assert missing == [], f"regex fallback under-reports: {missing}"


def test_the_corpus_and_fixtures_are_all_checked() -> None:
    names = {p.parent.name for p in SCRIPTS if p.name == "install.sh"}
    assert len(names) == 11
    assert any(p.name == "evasion_var_cmd.sh" for p in SCRIPTS)
