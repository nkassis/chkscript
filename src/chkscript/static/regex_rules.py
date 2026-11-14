"""Plain-regex fallback for the syntax-tree rules, with the same ids and messages.

Runs only when shfmt is missing or too old, or on a file shfmt cannot parse
(and on embedded code it cannot parse). Matching is per line of
`ScriptBundle.rules_text` (backslash continuations joined) with comments
stripped, so a commented-out command never fires and a comment never hides one.

The fallback has no syntax tree, so it over-reports by design: it cannot tell
a heredoc from a command, a constant from a variable, or which variable a
function was given. It must report at least every unsafe finding the
syntax-tree engine reports (tests/test_fallback_superset.py); where the engine
resolves something the text does not show, a pattern here is widened instead.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from chkscript.models import Finding, ScriptBundle, Severity
from chkscript.preprocess import COMMENT
from chkscript.static.rules.catalog import (
    AUTH_FILE,
    HOME,
    INSECURE_MODE,
    MESSAGES,
    RC_FILE,
    RULE_IDS,
    SCHEDULER_PATH,
    SECURITY_SERVICES,
)


class RegexRule(NamedTuple):
    rule_id: str
    pattern: re.Pattern[str]

    @property
    def message(self) -> str:
        return MESSAGES[self.rule_id]


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
_DECODER = (
    r"(?:\bbase64[ \t]+(?:.*[ \t])?(?:-d|--decode|-D)\b|\bxxd[ \t]+(?:.*[ \t])?-r"
    r"|\bopenssl[ \t]+enc[ \t]+(?:.*[ \t])?-d\b|\bgunzip[ \t]+(?:.*[ \t])?-c\b)"
)

LINE_RULES: tuple[RegexRule, ...] = (
    RegexRule(
        "curl-pipe-shell",
        re.compile(rf"(?:\b(?:curl|wget)\b|{_VAR_COMMAND}).*{_SHELL_STAGE}"),
    ),
    RegexRule(
        "eval-dynamic",
        re.compile(r"(?:^|[;&|({]|\b(?:then|do|else)\b)[ \t]*eval[ \t]+.*[$`]"),
    ),
    RegexRule("decode-to-shell", re.compile(rf"{_DECODER}.*{_SHELL_STAGE}")),
    RegexRule("write-system-auth-file", re.compile(rf"{_TARGET}{AUTH_FILE}")),
    RegexRule(
        "persistence-append",
        re.compile(
            rf"{_TARGET}(?:{RC_FILE}|{SCHEDULER_PATH})"
            r"|\|[ \t]*crontab[ \t]+-(?:[ \t]|$)|\bcrontab[ \t]+[^-\s]\S*"
        ),
    ),
    RegexRule(
        "insecure-permissions",
        re.compile(
            rf"\bchmod[ \t]+(?:-\S+[ \t]+)*{INSECURE_MODE}(?:[ \t]|$)"
            r"|\bchown[ \t]+(?:-\S+[ \t]+)*root\S*[ \t]+(?:\S+[ \t]+)*"
            rf"[\"']?(?:{HOME}|/tmp)(?:/|[ \t]|[\"']|$)"
        ),
    ),
    RegexRule(
        "rm-rf-variable",
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
_DOWNLOAD = re.compile(r"\b(?:curl|wget)\b")
_VERIFY = re.compile(r"\bsha256sum\b|\bshasum\b|\bgpg\b.*--verify|\bcosign\b")
# A word that may name a file: unquoted, with ${X} normalized to $X.
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

__all__ = ["LINE_RULES", "RULE_IDS", "UNVERIFIED_DOWNLOAD", "matches", "run"]


def code_lines(rules_text: str) -> list[tuple[int, str]]:
    """(line number, comment-stripped text) for each line of the joined text."""
    return [
        (number, COMMENT.sub("", line))
        for number, line in enumerate(rules_text.split("\n"), 1)
    ]


def matches(rules_text: str) -> list[tuple[str, int]]:
    """(rule id, line) for every rule that fires on the joined text."""
    lines = code_lines(rules_text)
    found = [
        (rule.rule_id, number)
        for number, line in lines
        for rule in LINE_RULES
        if rule.pattern.search(line)
    ]
    found += [(UNVERIFIED_DOWNLOAD.rule_id, n) for n in _unverified_lines(lines)]
    return found


def run(bundle: ScriptBundle) -> list[Finding]:
    return [
        _finding(bundle, rule_id, line) for rule_id, line in matches(bundle.rules_text)
    ]


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


def _unverified_lines(lines: list[tuple[int, str]]) -> list[int]:
    """Each `chmod +x` line whose files no verifier line names, if the script
    downloads anything. Per file, like the syntax-tree rule, but by text."""
    if not any(_DOWNLOAD.search(line) for _, line in lines):
        return []
    verified: set[str] = set()
    for _, line in lines:
        if _VERIFY.search(line):
            for token in _TOKEN.findall(line):
                verified |= _names(token)
    found: list[int] = []
    for number, line in lines:
        match = UNVERIFIED_DOWNLOAD.pattern.search(line)
        if match is None:
            continue
        rest = re.split(r";|&&|\|\|", line[match.end() :])[0]
        files = [t for t in _TOKEN.findall(rest) if re.search(r"[\w$]", t)]
        if not files or any(not (_names(f) & verified) for f in files):
            found.append(number)
    return found


def _finding(bundle: ScriptBundle, rule_id: str, line: int) -> Finding:
    return Finding(
        severity=Severity.UNSAFE,
        description=MESSAGES[rule_id],
        snippet=bundle.line_text(line),
        source="regex",
        rule_id=rule_id,
        file=bundle.file,
        line=line,
    )
