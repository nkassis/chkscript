"""Plain-regex fallback for the syntax-tree rules, with the same ids and messages.

Runs only when shfmt is missing or too old, or on a file shfmt cannot parse
(and on embedded code it cannot parse). Matching is per line of
`ScriptBundle.rules_text` (backslash continuations joined) with comments
stripped, so a commented-out command never fires and a comment never hides one.

The fallback has no syntax tree, so it over-reports by design: it cannot tell
a heredoc from a command, a constant from a variable, which variable a
function was given, or a guarded `rm -rf` from an unguarded one (every
`rm -rf` on a variable is `rm-rf-unguarded` here). It must report at least
every unsafe finding the syntax-tree engine reports
(tests/test_fallback_superset.py); where the engine resolves something the
text does not show, a pattern here is widened instead. Capability rules are
matched too, with the same ids, so a fallback report still has its "what this
script will do" section; they carry no floor.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from typing import NamedTuple

from chkscript.footprint import url_host
from chkscript.models import Finding, ScriptBundle
from chkscript.preprocess import COMMENT
from chkscript.static.rules.catalog import (
    APT_SOURCE,
    AUTH_FILE,
    CRON_PATH,
    GLOBAL_APT_KEY,
    HOME,
    INIT_PATH,
    RC_FILE,
    REPO_PATH,
    ROOT_GROUPS,
    RPM_REPO,
    SCHEDULER_PATH,
    SECURITY_SERVICES,
    SETID_MODE,
    SETID_SYSTEM_PATH,
    SYSTEM_PATH,
    SYSTEMD_PATH,
    WORLD_WRITABLE_MODE,
    finding,
)
from chkscript.static.rules.common import Hit


class RegexRule(NamedTuple):
    rule_id: str
    pattern: re.Pattern[str]


_VAR = r"\$\{?[A-Za-z_]\w*\}?"
# A word in command position (start of a command, after a wrapper).
_COMMAND_START = r"(?:^|[;&|({`]|\$\(|\b(?:then|do|else|sudo|env|exec|command)\b)[ \t]*"
# A variable run as a command: the engine may resolve it to curl or a shell.
_VAR_COMMAND = rf"{_COMMAND_START}{_VAR}(?=[ \t|;&)]|$)"
_SHELL_STAGE = rf"(?<!\|)\|(?!\|)[ \t]*(?:(?:sh|bash|zsh|sudo|doas)\b|\"?{_VAR})"
_WRITE = r"(?:>{1,2}|\btee[ \t]+(?:-a[ \t]+)?)"
_COPY_TO = r"\b(?:cp|mv|install|ln)[ \t]+[^;&|\n]*[ \t]"
_SED_I = r"\bsed[ \t]+-i\S*[ \t]+[^;&|\n]*[ \t]"
_TARGET = rf"(?:{_WRITE}|{_COPY_TO}|{_SED_I})[ \t]*[\"']?"
# Where a key or extracted archive goes: `gpg -o F`, `tar -C D`, `unzip -d D`.
_OUTPUT_TO = (
    r"(?:\bgpg\b[^;&|\n]*[ \t](?:-o|--output)|\btar\b[^;&|\n]*[ \t](?:-C|--directory)"
    r"|\bunzip\b[^;&|\n]*[ \t]-d)(?:[ \t]+|=)[\"']?"
)
_PATH = r"(?P<path>[^\s\"';|&)<>]+)"
_DECODER = (
    r"(?:\bbase64[ \t]+(?:.*[ \t])?(?:-d|--decode|-D)\b|\bxxd[ \t]+(?:.*[ \t])?-r"
    r"|\bopenssl[ \t]+enc[ \t]+(?:.*[ \t])?-d\b|\bgunzip[ \t]+(?:.*[ \t])?-c\b)"
)
_FETCH_SUBST = r"(?:\$\([^)]*|`[^`]*)\b(?:curl|wget)\b"
_EVAL = r"(?:^|[;&|({]|\b(?:then|do|else)\b)[ \t]*eval[ \t]+"

LINE_RULES: tuple[RegexRule, ...] = (
    RegexRule(
        "curl-pipe-shell",
        re.compile(rf"(?:\b(?:curl|wget)\b|{_VAR_COMMAND}).*{_SHELL_STAGE}"),
    ),
    RegexRule("decode-to-shell", re.compile(rf"{_DECODER}.*{_SHELL_STAGE}")),
    RegexRule("write-system-auth-file", re.compile(rf"{_TARGET}{AUTH_FILE}")),
    RegexRule(
        "rm-rf-unguarded",
        re.compile(
            r"\brm(?=(?:[ \t]+-[\w-]+)*[ \t]+(?:-[a-zA-Z]*[rR]|--recursive))"
            r"(?=(?:[ \t]+-[\w-]+)*[ \t]+(?:-[a-zA-Z]*f|--force))"
            r"(?:[ \t]+-[\w-]+)+[ \t]+[^;&|\n]*\$"
        ),
    ),
    RegexRule(
        "disable-security",
        re.compile(
            r"\bsetenforce[ \t]+0\b|\bufw[ \t]+(?:\S+[ \t]+)*disable\b"
            r"|\bsystemctl[ \t]+(?:\S+[ \t]+)*disable[ \t]+(?:\S+[ \t]+)*"
            rf"(?:{SECURITY_SERVICES})\b"
        ),
    ),
    RegexRule("http-download", re.compile(r"\b(?:curl|wget)\b.*\bhttp://")),
)

UNVERIFIED_DOWNLOAD = RegexRule(
    "unverified-download",
    re.compile(
        r"\bchmod[ \t]+(?:-\S+[ \t]+)*(?:[ugoa]*\+[rwst]*x|[0-7]*[1357][0-7]*)"
        r"(?=[ \t]|$)"
    ),
)

# The one rule the fallback never reports: telling a quoted or guarded
# variable from an unguarded one needs the tree, so every `rm -rf` on a
# variable is `rm-rf-unguarded` here.
TREE_ONLY: frozenset[str] = frozenset({"rm-rf-variable"})

_PERSISTENT = re.compile(rf"{_TARGET}{_PATH}")
_PERSISTENT_PATH = re.compile(rf"(?:{RC_FILE}|{SCHEDULER_PATH})")
_KINDS = (
    ("systemd", re.compile(SYSTEMD_PATH)),
    ("service", re.compile(INIT_PATH)),
    ("cron", re.compile(CRON_PATH)),
    ("rc", re.compile(RC_FILE)),
)
_CRONTAB = re.compile(r"\|[ \t]*crontab[ \t]+-(?:[ \t]|$)|\bcrontab[ \t]+[^-\s]\S*")
_CHMOD = re.compile(
    r"\bchmod[ \t]+(?:-\S+[ \t]+)*(?P<mode>\S+)(?P<files>(?:[ \t]+[^;&|\s]+)*)"
)
_CHOWN_ROOT = re.compile(
    r"\bchown[ \t]+(?:-\S+[ \t]+)*root\S*[ \t]+(?:\S+[ \t]+)*"
    rf"[\"']?(?:{HOME}|/tmp)(?:/|[ \t]|[\"']|$)"
)
_WORLD_WRITABLE = re.compile(rf"{WORLD_WRITABLE_MODE}$")
_SETID = re.compile(rf"{SETID_MODE}$")
_SETID_SYSTEM = re.compile(SETID_SYSTEM_PATH)
_WRITE_TO = re.compile(rf"(?:{_TARGET}|{_OUTPUT_TO}){_PATH}")
_SYSTEM = re.compile(SYSTEM_PATH)
_NOT_SYSTEM_WRITE = re.compile(
    rf"(?:{AUTH_FILE}|{RC_FILE}|{SCHEDULER_PATH}|{REPO_PATH})"
)
_APT_SOURCE = re.compile(APT_SOURCE)
_RPM_REPO = re.compile(RPM_REPO)
_GLOBAL_KEY = re.compile(GLOBAL_APT_KEY)
_REPO_TOOL = re.compile(
    r"\bapt-key[ \t]+(?:\S+[ \t]+)*(?:add|adv)\b|\brpm[ \t]+(?:\S+[ \t]+)*--import\b"
    r"|\badd-apt-repository\b|--add-repo\b|\bzypper[ \t]+(?:\S+[ \t]+)*(?:ar|addrepo)\b"
)
_ROOT_COMMAND = re.compile(rf"{_COMMAND_START}(?:sudo|doas)\b")
_ROOT_PROBE = re.compile(r"\$\([ \t]*id[ \t]+-[a-z]*u|\$\([ \t]*whoami\b|\$\{?E?UID\b")
_GROUPS = "|".join(ROOT_GROUPS)
_ROOT_GROUP = re.compile(
    r"\b(?:usermod|useradd)\b[^;&|\n]*(?:-[a-zA-Z]*G[ \t]*|--groups[= \t]+)"
    rf"[\"']?(?:\S*,)?(?P<g1>{_GROUPS})\b"
    rf"|\bgpasswd\b[^;&|\n]*(?:-a|--add)\b[^;&|\n]*[ \t][\"']?(?P<g2>{_GROUPS})\b"
    rf"|\b(?:adduser|addgroup)[ \t]+\S+[ \t]+[\"']?(?P<g3>{_GROUPS})\b"
)
_ASSIGN_FROM = re.compile(r"\b([A-Za-z_]\w*)=(.*)")

# A word that may name a file: unquoted, with ${X} normalized to $X.
_DOWNLOAD = re.compile(r"\b(?:curl|wget)\b")
_VERIFY = re.compile(r"\bsha256sum\b|\bshasum\b|\bgpg\b.*--verify|\bcosign\b")
_TOKEN = re.compile(r"[^\s\"'()=;|&<>`]+")
_SUFFIXES = (
    ".tar.gz",
    ".tar.xz",
    ".tar.zst",
    ".tar.bz2",
    ".tgz",
    ".tar",
    ".zip",
    ".gz",
    ".xz",
    ".zst",
    ".bz2",
    ".sha256sum",
    ".sha256",
    ".sha512",
    ".asc",
    ".sig",
    ".minisig",
)

__all__ = [
    "LINE_RULES",
    "REGEX_RULE_IDS",
    "TREE_ONLY",
    "UNVERIFIED_DOWNLOAD",
    "download_hosts",
    "matches",
    "run",
]


def code_lines(rules_text: str) -> list[tuple[int, str]]:
    """(line number, comment-stripped text) for each line of the joined text."""
    return [
        (number, COMMENT.sub("", line))
        for number, line in enumerate(rules_text.split("\n"), 1)
    ]


def _basename(path: str) -> str:
    return posixpath.basename(path.rstrip("/")) or path


def _fetching_vars(lines: list[tuple[int, str]]) -> set[str]:
    """Names assigned from `$(curl ...)`, or from such a name, anywhere."""
    names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for _, line in lines:
            for match in _ASSIGN_FROM.finditer(line):
                name, value = match.group(1), match.group(2)
                if name in names:
                    continue
                if re.search(_FETCH_SUBST, value) or any(
                    re.search(rf"\$\{{?{re.escape(n)}\b", value) for n in names
                ):
                    names.add(name)
                    changed = True
    return names


def _eval(lines: list[tuple[int, str]]) -> Iterator[Hit]:
    fetching = _fetching_vars(lines)
    fetched_var = (
        rf"|\$\{{?(?:{'|'.join(map(re.escape, sorted(fetching)))})\b"
        if fetching
        else ""
    )
    remote = re.compile(rf"{_EVAL}.*(?:{_FETCH_SUBST}{fetched_var})")
    dynamic = re.compile(rf"{_EVAL}.*[$`]")
    for number, line in lines:
        if remote.search(line):
            yield Hit("eval-remote", number)
        elif dynamic.search(line):
            yield Hit("eval-dynamic", number)


def _persistence(number: int, line: str) -> Iterator[Hit]:
    for match in _PERSISTENT.finditer(line):
        path = match.group("path")
        if _PERSISTENT_PATH.match(path):
            kind = next((k for k, p in _KINDS if p.match(path)), None)
            yield Hit("persistence-append", number, kind, _basename(path))
            return
    if _CRONTAB.search(line):
        yield Hit("persistence-append", number, "cron", "crontab")


def _permissions(number: int, line: str) -> Iterator[Hit]:
    for match in _CHMOD.finditer(line):
        mode = match.group("mode")
        if _WORLD_WRITABLE.match(mode):
            yield Hit("insecure-permissions", number)
            return
        if _SETID.match(mode):
            files = [f.strip("\"'") for f in match.group("files").split()]
            if files and all(_SETID_SYSTEM.match(f) and "$" not in f for f in files):
                yield Hit("setuid-system", number, subject=files[0])
            else:
                yield Hit("insecure-permissions", number)
            return
    if _CHOWN_ROOT.search(line):
        yield Hit("insecure-permissions", number)


def _writes(number: int, line: str) -> Iterator[Hit]:
    """system-path-write and package-repo-added, from what a line writes."""
    for match in _WRITE_TO.finditer(line):
        path = match.group("path")
        if _APT_SOURCE.match(path):
            scope = "scoped" if "signed-by=" in line else "global"
            yield Hit("package-repo-added", number, scope, _basename(path))
            return
        if _RPM_REPO.match(path) or _GLOBAL_KEY.match(path):
            yield Hit("package-repo-added", number, "global", _basename(path))
            return
        if _SYSTEM.match(path) and not _NOT_SYSTEM_WRITE.match(path):
            yield Hit("system-path-write", number, subject=path)
            return
    if _REPO_TOOL.search(line):
        yield Hit("package-repo-added", number, "global")


def _line_hits(number: int, line: str) -> Iterator[Hit]:
    for rule in LINE_RULES:
        if rule.pattern.search(line):
            yield Hit(rule.rule_id, number)
    yield from _persistence(number, line)
    yield from _permissions(number, line)
    yield from _writes(number, line)
    if _ROOT_COMMAND.search(line) or _ROOT_PROBE.search(line):
        yield Hit("runs-as-root", number)
    group = _ROOT_GROUP.search(line)
    if group is not None:
        name = group.group("g1") or group.group("g2") or group.group("g3")
        yield Hit("root-equivalent-group", number, subject=name)


def matches(rules_text: str) -> list[Hit]:
    """Every rule hit on the joined text."""
    lines = code_lines(rules_text)
    found = [hit for number, line in lines for hit in _line_hits(number, line)]
    found += _eval(lines)
    found += _unverified(lines)
    return found


def run(bundle: ScriptBundle) -> list[Finding]:
    return [
        finding(bundle, h.rule_id, h.line, "regex", h.variant, h.subject)
        for h in matches(bundle.rules_text)
    ]


_ASSIGNMENT = re.compile(r"^[ \t]*(?:export[ \t]+|local[ \t]+|readonly[ \t]+)?\w+=")


def download_hosts(bundle: ScriptBundle) -> list[str]:
    """Without a tree: hosts of the URL candidates on a line that runs curl
    or wget, or that assigns a variable (which may feed one)."""
    lines = bundle.rules_text.split("\n")
    hosts: list[str] = []
    for url in bundle.urls:
        line = COMMENT.sub("", lines[url.line - 1]) if url.line <= len(lines) else ""
        if _DOWNLOAD.search(line) or _ASSIGNMENT.match(line):
            hosts.append(url_host(url.url))
    return hosts


def _names(token: str) -> set[str]:
    """A path token's names: itself, its basename, both without a suffix."""
    token = re.sub(r"\$\{(\w+)\}", r"$\1", token).rstrip("/")
    names: set[str] = set()
    for name in (token, token.rsplit("/", 1)[-1]):
        if name in ("", "-", "/dev/null"):
            continue
        names.add(name)
        names.update(name[: -len(s)] for s in _SUFFIXES if name.endswith(s))
    names.discard("")
    return names


def _unverified(lines: list[tuple[int, str]]) -> list[Hit]:
    """Each `chmod +x` line whose files no verifier line names, if the script
    downloads anything. Per file, like the syntax-tree rule, but by text."""
    if not any(_DOWNLOAD.search(line) for _, line in lines):
        return []
    verified: set[str] = set()
    for _, line in lines:
        if _VERIFY.search(line):
            for token in _TOKEN.findall(line):
                verified |= _names(token)
    found: list[Hit] = []
    for number, line in lines:
        match = UNVERIFIED_DOWNLOAD.pattern.search(line)
        if match is None:
            continue
        rest = re.split(r";|&&|\|\|", line[match.end() :])[0]
        files = [t for t in _TOKEN.findall(rest) if re.search(r"[\w$]", t)]
        unverified = [f for f in files if not (_names(f) & verified)]
        if not files or unverified:
            subject = _basename(unverified[0]) if unverified else None
            found.append(Hit(UNVERIFIED_DOWNLOAD.rule_id, number, subject=subject))
    return found


# Every rule id this fallback can report.
REGEX_RULE_IDS: frozenset[str] = frozenset(
    {r.rule_id for r in LINE_RULES}
    | {
        "eval-remote",
        "eval-dynamic",
        "persistence-append",
        "insecure-permissions",
        "setuid-system",
        "system-path-write",
        "package-repo-added",
        "runs-as-root",
        "root-equivalent-group",
        UNVERIFIED_DOWNLOAD.rule_id,
    }
)
