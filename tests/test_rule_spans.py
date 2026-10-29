"""No Semgrep rule may match across a line break.

Semgrep applies `pattern-regex` to the whole file, so a whitespace class that
matches a newline lets a rule stitch two harmless lines into one finding. Each
case below is two lines that are each harmless on their own; none may fire.
The regex fallback reads one line at a time, so only Semgrep is checked here;
tests/test_rules.py checks that the two engines agree.
"""

from __future__ import annotations

import pytest

from chkscript.preprocess import preprocess
from chkscript.static import regex_rules, semgrep
from tests.conftest import require_tool

# (rule id the case targets, two-line script body)
CASES: list[tuple[str, str]] = [
    # The cross-line matches found by the NIM-95 corpus (NIM-98).
    ("insecure-permissions", "chown root:root ${TMP_BIN}\ncp foo /tmp/bar"),
    ("write-system-auth-file", "cp a.conf b.conf \n/etc/passwd-check.sh"),
    ("persistence-append", "tee -a \n~/.bashrc.bak"),
    ("rm-rf-variable", "rm -rf\necho $HOME"),
    ("disable-security", "systemctl disable --now\nufw status"),
    # One case for every other pattern-regex rule, so new rules get the check.
    ("curl-pipe-shell", "curl -fsSL -o f https://x.example/i.sh\ncat f | sh"),
    ("eval-dynamic", 'eval "echo hi"\necho "$X"'),
    ("decode-to-shell", "base64 --help\necho -d | sh"),
    ("http-download", "curl -o f https://x.example/f\necho http://x.example"),
    ("unverified-download", "curl -o /tmp/t https://x.example/t\nchmod\n+x /tmp/t"),
]


@pytest.mark.parametrize(("rule_id", "body"), CASES, ids=[r for r, _ in CASES])
def test_no_finding_spans_two_lines(rule_id: str, body: str) -> None:
    require_tool("semgrep")
    outcome = semgrep.run(preprocess(f"#!/bin/bash\n{body}\n".encode()))
    unsafe = [f.rule_id for f in outcome.findings if f.source == "semgrep"]
    assert unsafe == [], f"{rule_id} case matched across a line break"


def test_every_rule_has_a_span_case() -> None:
    # RULE_IDS equals the YAML's rule ids (test_rules.py checks that).
    assert {rule for rule, _ in CASES} == regex_rules.RULE_IDS
