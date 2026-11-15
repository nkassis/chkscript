"""No rule may stitch two harmless lines into one finding.

Each case below is two lines that are each harmless on their own; none may
fire under either engine. This guarded the old Semgrep rules, whose
whole-file regexes could match across a newline (NIM-98); it stays as a check
on both current engines, and test_rules.py runs these cases through the
fallback-superset check too.
"""

from __future__ import annotations

import pytest

from chkscript.preprocess import preprocess
from chkscript.static import engine, regex_rules, rules
from tests.conftest import require_tool

# (rule id the case targets, two-line script body)
CASES: list[tuple[str, str]] = [
    ("insecure-permissions", "chown root:root ${TMP_BIN}\ncp foo /tmp/bar"),
    ("write-system-auth-file", "cp a.conf b.conf \n/etc/passwd-check.sh"),
    ("persistence-append", "tee -a \n~/.bashrc.bak"),
    ("rm-rf-variable", "rm -rf\necho $HOME"),
    ("disable-security", "systemctl disable --now\nufw status"),
    ("curl-pipe-shell", "curl -fsSL -o f https://x.example/i.sh\ncat f | sh"),
    ("eval-dynamic", 'eval "echo hi"\necho "$X"'),
    ("decode-to-shell", "base64 --help\necho -d | sh"),
    ("http-download", "curl -o f https://x.example/f\necho http://x.example"),
    ("unverified-download", "curl -o /tmp/t https://x.example/t\nchmod\n+x /tmp/t"),
]


@pytest.mark.parametrize("engine_name", ["shfmt", "regex"])
@pytest.mark.parametrize(("rule_id", "body"), CASES, ids=[r for r, _ in CASES])
def test_no_finding_spans_two_lines(engine_name: str, rule_id: str, body: str) -> None:
    bundle = preprocess(f"#!/bin/bash\n{body}\n".encode())
    if engine_name == "shfmt":
        require_tool("shfmt")
        findings = engine.scan(bundle).findings
    else:
        findings = regex_rules.run(bundle)
    unsafe = [f.rule_id for f in findings if f.rule_id in rules.RULE_IDS]
    assert unsafe == [], f"{rule_id} case matched across a line break"


def test_every_rule_has_a_span_case() -> None:
    assert {rule for rule, _ in CASES} == rules.RULE_IDS
