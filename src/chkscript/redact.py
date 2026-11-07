"""Find hardcoded secrets in a script, report them, and mask them in what leaves.

Detection is deliberately basic: a handful of well-known token formats plus a
name-based assignment heuristic. Missed secrets are expected; this is not a
secret scanner. Each distinct value gets one stable placeholder,
`[SECRET-<n>:<kind>]`, so masked text still shows where a value flows.

The static rules and the report's hashes always see the original bytes; only
the model prompt and the rendered report are masked.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable
from dataclasses import dataclass

from chkscript.models import (
    AnalysisResult,
    DetectedSecret,
    Finding,
    ScriptBundle,
    Severity,
)

RULE_ID = "hardcoded-secret"

REMEDIATION = (
    "move this to an env file or pass it through the environment; never "
    "hardcode credentials in a script."
)

# Known formats, most specific first: a span claimed by an earlier pattern is
# not matched again by a later one.
_FORMATS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private-key",
        re.compile(
            # The body stops at the first `--`, so a hostile file of unclosed
            # headers costs linear time, not quadratic.
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:[^-]|-(?!-))*"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
    ),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("github-token", re.compile(r"\bgh[po]_[A-Za-z0-9]{36}\b")),
    ("github-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("slack-token", re.compile(r"\bxox[bp]-[A-Za-z0-9-]{10,}")),
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
]

# An AWS secret access key: 40 base64 characters, looked for only when the
# script also holds an AKIA key id (its pair).
_AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")

_SECRET_NAME_PARTS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "API_KEY")
# NAME=literal, where the literal is a double-quoted string with no expansion, a
# single-quoted string, or an unquoted word with no expansion.
_ASSIGNMENT = re.compile(
    r"""(?<![\w$])([A-Za-z_]\w*)="""
    r"""(?:"([^"$`\\]*)"|'([^']*)'|([^\s"'$`\\;|&<>()]+)(?=[\s;|&)]|$))""",
    re.MULTILINE,
)
_MIN_ASSIGNED_LENGTH = 8
# `.env.example`-style values that document a variable rather than set it.
_PLACEHOLDER = re.compile(
    r"your[-_ ]|[-_ ]here$|change[-_ ]?me|replace[-_ ]?me|example|placeholder"
    r"|dummy|redacted|\.\.\.|^<.*>$|^(.)\1*$",
    re.IGNORECASE,
)
_ASSIGNED_KIND = "credential-variable"

# A line of a multi-line secret is masked on its own when at least this long,
# so a one-line snippet inside a private key cannot leak a fragment of it.
_MIN_FRAGMENT = 8


@dataclass(frozen=True)
class _Match:
    start: int
    end: int
    kind: str


class _Claims:
    """Non-overlapping spans, kept sorted by start, with an O(log n) overlap test.

    A hostile script can hold thousands of candidate secrets, so nothing here
    may rescan every span already claimed.
    """

    def __init__(self) -> None:
        self._starts: list[int] = []
        self.matches: list[_Match] = []

    def claim(self, match: _Match) -> None:
        i = bisect.bisect_left(self._starts, match.start)
        if i > 0 and self.matches[i - 1].end > match.start:
            return
        if i < len(self.matches) and self.matches[i].start < match.end:
            return
        self._starts.insert(i, match.start)
        self.matches.insert(i, match)


def _format_matches(text: str, claims: _Claims) -> None:
    for kind, pattern in _FORMATS:
        for m in pattern.finditer(text):
            claims.claim(_Match(m.start(), m.end(), kind))
    if any(m.kind == "aws-access-key-id" for m in claims.matches):
        for m in _AWS_SECRET.finditer(text):
            value = m.group(0)
            if any(c.isupper() for c in value) and any(c.islower() for c in value):
                claims.claim(_Match(m.start(), m.end(), "aws-secret-key"))


def _is_secret_literal(name: str, value: str) -> bool:
    if not any(part in name.upper() for part in _SECRET_NAME_PARTS):
        return False
    if len(value) < _MIN_ASSIGNED_LENGTH or _PLACEHOLDER.search(value):
        return False
    # A URL or path names where a secret lives, not the secret itself.
    return "://" not in value and not value.startswith(("/", "~/", "./"))


def _assignment_matches(text: str, claims: _Claims) -> None:
    for m in _ASSIGNMENT.finditer(text):
        group = next(g for g in (2, 3, 4) if m.group(g) is not None)
        if _is_secret_literal(m.group(1), m.group(group)):
            claims.claim(_Match(m.start(group), m.end(group), _ASSIGNED_KIND))


def _alternation(literals: Iterable[str]) -> re.Pattern[str]:
    # Longest first, so a whole value wins over a shorter value or fragment.
    ordered = sorted(literals, key=len, reverse=True)
    return re.compile("|".join(re.escape(a) for a in ordered))


def _occurrence_lines(text: str, values: dict[str, _Match]) -> dict[str, list[int]]:
    """Lines each value occurs on, from one scan of `text` for all of them."""
    newlines = [i for i, c in enumerate(text) if c == "\n"]
    lines: dict[str, dict[int, None]] = {value: {} for value in values}
    for m in _alternation(values).finditer(text):
        lines[m.group(0)][bisect.bisect_right(newlines, m.start()) + 1] = None
    for value, first in values.items():
        # A value can be hidden inside a longer one's occurrence; it still
        # occurs where it was detected.
        if not lines[value]:
            lines[value][bisect.bisect_right(newlines, first.start) + 1] = None
    return {value: sorted(found) for value, found in lines.items()}


def detect(text: str) -> list[DetectedSecret]:
    """Every distinct secret value in `text`, numbered by first appearance."""
    claims = _Claims()
    _format_matches(text, claims)
    _assignment_matches(text, claims)

    first: dict[str, _Match] = {}
    for match in claims.matches:  # sorted by start
        first.setdefault(text[match.start : match.end], match)
    if not first:
        return []
    lines = _occurrence_lines(text, first)

    return [
        DetectedSecret(
            value=value,
            kind=match.kind,
            placeholder=f"[SECRET-{n}:{match.kind}]",
            lines=lines[value],
        )
        for n, (value, match) in enumerate(first.items(), 1)
    ]


class Masker:
    """Replaces every detected secret with its placeholder.

    Build one per set of secrets and reuse it: compiling the pattern costs time
    proportional to the number of secrets.
    """

    def __init__(self, secrets: list[DetectedSecret]) -> None:
        self._table = _replacements(secrets)
        self._pattern = _alternation(self._table) if self._table else None

    def __call__(self, text: str) -> str:
        if self._pattern is None or not text:
            return text
        return self._pattern.sub(lambda m: self._table[m.group(0)], text)

    def optional(self, text: str | None) -> str | None:
        return None if text is None else self(text)


def _replacements(secrets: list[DetectedSecret]) -> dict[str, str]:
    """Each value, and each long line of a multi-line value, to its placeholder.

    A multi-line value keeps its newlines so line numbers do not move.
    """
    out: dict[str, str] = {}
    for secret in secrets:
        out[secret.value] = secret.placeholder + "\n" * secret.value.count("\n")
        if "\n" in secret.value:
            for piece in secret.value.split("\n"):
                piece = piece.strip()
                if len(piece) >= _MIN_FRAGMENT:
                    out.setdefault(piece, secret.placeholder)
    return out


def mask(text: str, secrets: list[DetectedSecret]) -> str:
    """`text` with every occurrence of every secret replaced by its placeholder.

    For one string only; to mask many, build a `Masker` once.
    """
    return Masker(secrets)(text)


def mask_finding(finding: Finding, masker: Masker) -> Finding:
    """Every text field of a finding, masked."""
    return finding.model_copy(
        update={
            "description": masker(finding.description),
            "snippet": masker.optional(finding.snippet),
            "line_reference": masker.optional(finding.line_reference),
        }
    )


def mask_result(
    result: AnalysisResult, secrets: list[DetectedSecret]
) -> AnalysisResult:
    """Mask every text field of a report before it is rendered."""
    if not secrets:
        return result
    masker = Masker(secrets)
    return result.model_copy(
        update={
            "summary": masker(result.summary),
            "notes": [masker(note) for note in result.notes],
            "findings": [mask_finding(f, masker) for f in result.findings],
        }
    )


def _lines_label(lines: list[int]) -> str:
    noun = "line" if len(lines) == 1 else "lines"
    return f"{noun} {', '.join(str(n) for n in lines)}"


def _finding(
    bundle: ScriptBundle,
    group: list[DetectedSecret],
    script_lines: list[str],
    masker: Masker,
) -> Finding:
    line = group[0].lines[0]
    lines = sorted({n for s in group for n in s.lines})
    names = " and ".join(s.placeholder for s in group)
    noun = "credential" if len(group) == 1 else "credentials"
    raw_line = script_lines[line - 1] if line <= len(script_lines) else ""
    return Finding(
        severity=Severity.WARNING,
        category="capability",
        description=(
            f"Hardcoded {noun} {names} on {_lines_label(lines)}: {REMEDIATION}"
        ),
        snippet=masker(raw_line) or None,
        source="chkscript",
        rule_id=RULE_ID,
        file=bundle.file,
        line=line,
    )


def secret_findings(bundle: ScriptBundle) -> list[Finding]:
    """One `hardcoded-secret` finding per distinct value.

    Values first seen on the same line share one finding: findings merge on
    `(file, line, rule_id)`, so two would collapse into one anyway.
    """
    if not bundle.secrets:
        return []
    by_line: dict[int, list[DetectedSecret]] = {}
    for secret in bundle.secrets:
        by_line.setdefault(secret.lines[0], []).append(secret)
    masker = Masker(bundle.secrets)
    script_lines = bundle.text.split("\n")
    return [
        _finding(bundle, group, script_lines, masker)
        for _, group in sorted(by_line.items())
    ]


def notice(secrets: list[DetectedSecret]) -> str | None:
    """The single do-not-share line for stderr, or None when nothing was found."""
    if not secrets:
        return None
    kinds = ", ".join(dict.fromkeys(s.kind for s in secrets))
    return (
        f"This script contains what looks like a live credential ({kinds}). "
        "This report masks it, but the script file itself does not: do not "
        "commit, share or paste the script."
    )
