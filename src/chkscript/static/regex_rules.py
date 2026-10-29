"""Plain-regex version of the Semgrep ruleset, with the same rule ids and messages.

Runs when Semgrep is not on PATH, and on any file Semgrep could not fully parse.
Matching is per logical line (backslash continuations joined) with comments
stripped, so a commented-out command never fires and a comment never hides one.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from chkscript.models import Finding, ScriptBundle, Severity


class RegexRule(NamedTuple):
    rule_id: str
    message: str
    pattern: re.Pattern[str]


_SHELL_STAGE = r"(?<!\|)\|(?!\|)[ \t]*(?:sh|bash|zsh|sudo)\b"
_HOME = r"(?:~|\$HOME|\$\{HOME\})"
_WRITE = r"(?:>{1,2}|\btee[ \t]+(?:-a[ \t]+)?)"
_COPY_TO = r"\b(?:cp|mv|install)[ \t]+[^;&|\n]*[ \t]"
_DECODER = (
    r"(?:\bbase64[ \t]+(?:.*[ \t])?(?:-d|--decode|-D)\b|\bxxd[ \t]+(?:.*[ \t])?-r"
    r"|\bopenssl[ \t]+enc[ \t]+(?:.*[ \t])?-d\b|\bgunzip[ \t]+(?:.*[ \t])?-c\b)"
)
_SECURITY_SERVICES = (
    "apparmor|firewalld|ufw|auditd|fail2ban|iptables|nftables|clamav-daemon"
    "|clamd|falcon-sensor|osqueryd|wazuh-agent|selinux"
)

LINE_RULES: tuple[RegexRule, ...] = (
    RegexRule(
        "curl-pipe-shell",
        "Downloaded content is piped straight into a shell, so whatever the server "
        "returns runs unreviewed.",
        re.compile(rf"\b(?:curl|wget)\b.*{_SHELL_STAGE}"),
    ),
    RegexRule(
        "eval-dynamic",
        "eval runs a string built from a variable or command output, which hides "
        "what actually executes.",
        re.compile(r"(?:^|[;&|({]|\b(?:then|do|else)\b)[ \t]*eval[ \t]+.*[$`]"),
    ),
    RegexRule(
        "decode-to-shell",
        "Decoded or decompressed data is fed to a shell, a common way to hide a "
        "payload from review.",
        re.compile(rf"{_DECODER}.*{_SHELL_STAGE}"),
    ),
    RegexRule(
        "write-system-auth-file",
        "The script writes to a system authentication or loader file, which can "
        "grant root or hijack every process.",
        re.compile(
            rf"(?:{_WRITE}|\b(?:cp|mv|install|ln)[ \t]+[^;&|\n]*[ \t]"
            r"|\bsed[ \t]+-i\S*[ \t]+[^;&|\n]*[ \t])"
            r"[ \t]*[\"']?/etc/(?:sudoers|passwd\b|shadow\b|ld\.so\.preload\b)"
        ),
    ),
    RegexRule(
        "persistence-append",
        "The script installs itself to run again later via a shell rc file, "
        "crontab or systemd unit.",
        re.compile(
            rf"(?:{_WRITE}[ \t]*[\"']?{_HOME}/\.(?:bashrc|bash_profile|profile|zshrc)\b"
            r"|\|[ \t]*crontab[ \t]+-(?:[ \t]|$)|\bcrontab[ \t]+[^-\s]\S*"
            rf"|(?:{_WRITE}|{_COPY_TO})[ \t]*[\"']?(?:/etc/cron|/var/spool/cron"
            rf"|/etc/systemd/|/lib/systemd/|/usr/lib/systemd/|{_HOME}/\.config/systemd/))"
        ),
    ),
    RegexRule(
        "insecure-permissions",
        "World-writable, setuid/setgid, or root-owned files in a user-writable "
        "location let other users escalate privileges.",
        re.compile(
            r"\bchmod[ \t]+(?:-\S+[ \t]+)*"
            r"(?:0?777|[ugoa]*\+[rwxt]*s[rwxt]*|0?[2467][0-7]{3})(?:[ \t]|$)"
            r"|\bchown[ \t]+(?:-\S+[ \t]+)*root\S*[ \t]+(?:\S+[ \t]+)*"
            rf"[\"']?(?:{_HOME}|/tmp)(?:/|[ \t]|[\"']|$)"
        ),
    ),
    RegexRule(
        "rm-rf-variable",
        "rm -rf on a path containing a variable deletes the wrong tree, or /, when "
        "the variable is empty or attacker-set.",
        re.compile(
            r"\brm(?=(?:[ \t]+-[\w-]+)*[ \t]+(?:-[a-zA-Z]*[rR]|--recursive))"
            r"(?=(?:[ \t]+-[\w-]+)*[ \t]+(?:-[a-zA-Z]*f|--force))"
            r"(?:[ \t]+-[\w-]+)+[ \t]+[^;&|\n]*\$"
        ),
    ),
    RegexRule(
        "disable-security",
        "The script turns off a host security control (SELinux, a firewall, or a "
        "security service).",
        re.compile(
            r"\bsetenforce[ \t]+0\b|\bufw[ \t]+disable\b"
            r"|\bsystemctl[ \t]+(?:--\S+[ \t]+)*disable[ \t]+(?:--\S+[ \t]+)*"
            rf"(?:{_SECURITY_SERVICES})\b"
        ),
    ),
    RegexRule(
        "http-download",
        "A download over plain http:// can be read or replaced by anyone on the "
        "network path.",
        re.compile(r"\b(?:curl|wget)\b.*\bhttp://"),
    ),
)

UNVERIFIED_DOWNLOAD = RegexRule(
    "unverified-download",
    "An executable is downloaded with no sha256sum, shasum, gpg --verify or cosign "
    "check anywhere in the script.",
    re.compile(
        r"\bchmod[ \t]+(?:-\S+[ \t]+)*(?:[ugoa]*\+[rwst]*x|[0-7]*[1357][0-7]*\b)"
    ),
)
_DOWNLOAD = re.compile(r"\b(?:curl|wget)\b")
_VERIFY = re.compile(r"\bsha256sum\b|\bshasum\b|\bgpg\b.*--verify|\bcosign\b")

RULE_IDS: frozenset[str] = frozenset(
    rule.rule_id for rule in (*LINE_RULES, UNVERIFIED_DOWNLOAD)
)


# A `#` starts a comment at the start of a word; `$#` and URL fragments do not.
_COMMENT = re.compile(r"(?:^|(?<=[ \t]))#.*$")


def logical_lines(text: str) -> list[tuple[int, str]]:
    """(first physical line number, comment-stripped text) per logical line."""
    result: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 1
    for number, physical in enumerate(text.split("\n"), 1):
        if not pending:
            start = number
        stripped = _COMMENT.sub("", physical)
        if stripped.endswith("\\") and not stripped.endswith("\\\\"):
            pending.append(stripped[:-1])
            continue
        pending.append(stripped)
        result.append((start, " ".join(pending)))
        pending = []
    if pending:
        result.append((start, " ".join(pending)))
    return result


def run(bundle: ScriptBundle) -> list[Finding]:
    lines = logical_lines(bundle.text)
    findings = [
        _finding(bundle, rule, number)
        for number, line in lines
        for rule in LINE_RULES
        if rule.pattern.search(line)
    ]
    unverified = _unverified_download_line(lines)
    if unverified is not None:
        findings.append(_finding(bundle, UNVERIFIED_DOWNLOAD, unverified))
    return findings


def _unverified_download_line(lines: list[tuple[int, str]]) -> int | None:
    """Line of the first `chmod +x`, if the script downloads and never verifies."""
    if not any(_DOWNLOAD.search(line) for _, line in lines):
        return None
    if any(_VERIFY.search(line) for _, line in lines):
        return None
    for number, line in lines:
        if UNVERIFIED_DOWNLOAD.pattern.search(line):
            return number
    return None


def _finding(bundle: ScriptBundle, rule: RegexRule, line: int) -> Finding:
    return Finding(
        severity=Severity.UNSAFE,
        description=rule.message,
        snippet=bundle.line_text(line),
        source="regex",
        rule_id=rule.rule_id,
        file=bundle.file,
        line=line,
    )
