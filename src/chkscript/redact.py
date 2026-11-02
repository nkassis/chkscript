"""Find hardcoded secrets in a script, report them, and mask them in what leaves.

Detection is deliberately basic: a handful of well-known token formats plus a
name-based assignment heuristic. Missed secrets are expected; this is not a
secret scanner. Each distinct value gets one stable placeholder,
`[SECRET-<n>:<kind>]`, so masked text still shows where a value flows.

The static rules and the report's hashes always see the original bytes; only
the model prompt and the rendered report are masked.
"""

from __future__ import annotations

import re
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

    def overlaps(self, other: _Match) -> bool:
        return self.start < other.end and other.start < self.end


def _claim(found: list[_Match], match: _Match) -> None:
    if not any(match.overlaps(m) for m in found):
        found.append(match)


def _format_matches(text: str) -> list[_Match]:
    found: list[_Match] = []
    for kind, pattern in _FORMATS:
        for m in pattern.finditer(text):
            _claim(found, _Match(m.start(), m.end(), kind))
    if any(m.kind == "aws-access-key-id" for m in found):
        for m in _AWS_SECRET.finditer(text):
            value = m.group(0)
            if any(c.isupper() for c in value) and any(c.islower() for c in value):
                _claim(found, _Match(m.start(), m.end(), "aws-secret-key"))
    return found


def _is_secret_literal(name: str, value: str) -> bool:
    if not any(part in name.upper() for part in _SECRET_NAME_PARTS):
        return False
    if len(value) < _MIN_ASSIGNED_LENGTH or _PLACEHOLDER.search(value):
        return False
    # A URL or path names where a secret lives, not the secret itself.
    return "://" not in value and not value.startswith(("/", "~/", "./"))


def _assignment_matches(text: str, found: list[_Match]) -> None:
    for m in _ASSIGNMENT.finditer(text):
        group = next(g for g in (2, 3, 4) if m.group(g) is not None)
        if _is_secret_literal(m.group(1), m.group(group)):
            _claim(found, _Match(m.start(group), m.end(group), _ASSIGNED_KIND))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _occurrence_lines(text: str, value: str) -> list[int]:
    lines: list[int] = []
    start = text.find(value)
    while start != -1:
        line = _line_of(text, start)
        if line not in lines:
            lines.append(line)
        start = text.find(value, start + len(value))
    return lines


def detect(text: str) -> list[DetectedSecret]:
    """Every distinct secret value in `text`, numbered by first appearance."""
    found = _format_matches(text)
    _assignment_matches(text, found)

    kinds: dict[str, str] = {}
    for match in sorted(found, key=lambda m: m.start):
        kinds.setdefault(text[match.start : match.end], match.kind)

    return [
        DetectedSecret(
            value=value,
            kind=kind,
            placeholder=f"[SECRET-{n}:{kind}]",
            lines=_occurrence_lines(text, value),
        )
        for n, (value, kind) in enumerate(kinds.items(), 1)
    ]


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
    """`text` with every occurrence of every secret replaced by its placeholder."""
    if not secrets or not text:
        return text
    table = _replacements(secrets)
    # Longest first, so a whole value wins over any fragment of it.
    alternatives = sorted(table, key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(a) for a in alternatives))
    return pattern.sub(lambda m: table[m.group(0)], text)


def _mask_optional(text: str | None, secrets: list[DetectedSecret]) -> str | None:
    return None if text is None else mask(text, secrets)


def _mask_finding(finding: Finding, secrets: list[DetectedSecret]) -> Finding:
    return finding.model_copy(
        update={
            "description": mask(finding.description, secrets),
            "snippet": _mask_optional(finding.snippet, secrets),
            "line_reference": _mask_optional(finding.line_reference, secrets),
        }
    )


def mask_result(
    result: AnalysisResult, secrets: list[DetectedSecret]
) -> AnalysisResult:
    """Mask every text field of a report before it is rendered."""
    if not secrets:
        return result
    return result.model_copy(
        update={
            "summary": mask(result.summary, secrets),
            "notes": [mask(note, secrets) for note in result.notes],
            "findings": [_mask_finding(f, secrets) for f in result.findings],
        }
    )


def _lines_label(lines: list[int]) -> str:
    noun = "line" if len(lines) == 1 else "lines"
    return f"{noun} {', '.join(str(n) for n in lines)}"


def _finding(bundle: ScriptBundle, group: list[DetectedSecret]) -> Finding:
    line = group[0].lines[0]
    lines = sorted({n for s in group for n in s.lines})
    names = " and ".join(s.placeholder for s in group)
    noun = "credential" if len(group) == 1 else "credentials"
    return Finding(
        severity=Severity.WARNING,
        category="capability",
        description=(
            f"Hardcoded {noun} {names} on {_lines_label(lines)}: {REMEDIATION}"
        ),
        snippet=mask(bundle.line_text(line) or "", bundle.secrets) or None,
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
    by_line: dict[int, list[DetectedSecret]] = {}
    for secret in bundle.secrets:
        by_line.setdefault(secret.lines[0], []).append(secret)
    return [_finding(bundle, group) for _, group in sorted(by_line.items())]


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
