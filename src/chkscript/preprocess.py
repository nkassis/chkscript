"""Turn raw script bytes into a ScriptBundle: decoded, numbered, hashed, URLs found."""

from __future__ import annotations

import hashlib
import re
from typing import Literal

from chkscript.models import ENTRY_FILE, ExtractedUrl, ScriptBundle

MAX_SCRIPT_SIZE = 500 * 1024  # 500KB

# A URL literal ends at whitespace, a quote, or shell punctuation that cannot be
# part of an unquoted word. `$`, `{` and `}` are kept so variable-built URLs
# such as "https://github.com/${REPO}/releases" are captured whole.
_URL = re.compile(r"""https?://[^\s'"<>`|;()]+""")
_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)*)?"
    r"([A-Za-z_]\w*)=(\S.*)$"
)
_FETCHER = re.compile(r"\b(?:curl|wget|fetch|git\s+clone)\b")


class ScriptTooLargeError(Exception):
    pass


def preprocess(raw: bytes, file: str = ENTRY_FILE) -> ScriptBundle:
    if len(raw) > MAX_SCRIPT_SIZE:
        raise ScriptTooLargeError(
            f"Script exceeds maximum size of {MAX_SCRIPT_SIZE // 1024}KB"
        )
    text = normalize(raw.decode("utf-8", errors="replace"))
    return ScriptBundle(
        file=file,
        text=text,
        numbered=number_lines(text),
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        urls=extract_urls(text),
    )


def normalize(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def number_lines(text: str) -> str:
    """Prefix each line with its number, e.g. `  42 | curl ...`."""
    lines = _lines(text)
    width = max(4, len(str(len(lines))))
    return "\n".join(f"{n:>{width}} | {line}" for n, line in enumerate(lines, 1))


def _kind(url: str) -> Literal["literal", "variable"]:
    return "variable" if "$" in url or "`" in url else "literal"


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _references(line: str, name: str) -> bool:
    return re.search(rf"\$(?:{name}\b|\{{{name}\}})", line) is not None


def extract_urls(text: str) -> list[ExtractedUrl]:
    """Every http(s) literal, plus assignments whose variable feeds a fetcher."""
    lines = _lines(text)
    found: dict[tuple[str, int], ExtractedUrl] = {}

    for number, line in enumerate(lines, 1):
        for match in _URL.finditer(line):
            url = match.group(0)
            found[(url, number)] = ExtractedUrl(url=url, line=number, kind=_kind(url))

    fetch_lines = [line for line in lines if _FETCHER.search(line)]
    for number, line in enumerate(lines, 1):
        assignment = _ASSIGNMENT.match(line)
        if assignment is None or _URL.search(line):
            continue  # not an assignment, or its URL literal is already recorded
        name, value = assignment.group(1), _unquote(assignment.group(2))
        if "$" not in value and "://" not in value:
            continue
        if any(_references(fetch_line, name) for fetch_line in fetch_lines):
            found[(value, number)] = ExtractedUrl(
                url=value, line=number, kind=_kind(value)
            )

    return sorted(found.values(), key=lambda u: (u.line, u.url))
