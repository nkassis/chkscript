"""shfmt adapter: the script's syntax tree, from `shfmt --to-json`.

Every script is parsed as bash whatever its shebang: POSIX `sh` scripts parse
the same way in bash mode, and a shebang is text the script's author chose.
The tree is read by static/commands.py; nothing here judges the script.
"""

from __future__ import annotations

import functools
import json
import re
import shutil
import subprocess
from typing import Any

# The first release whose --to-json writes operators as strings (">>", "|")
# rather than integers (mvdan/sh#1321); the command model depends on that.
MIN_VERSION = (3, 14, 0)
PARSE_FAILURE_RULE = "parse-failure"
PARSE_FAILURE_MESSAGE = "shfmt could not parse this file; static coverage reduced."
_TIMEOUT_SECONDS = 60
_VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
# shfmt reports errors as `<standard input>:LINE:COL: message`.
_ERROR_POSITION = re.compile(r"^(?:<standard input>:)?(\d+):(\d+): ")

Node = dict[str, Any]


class ShfmtError(Exception):
    """shfmt could not produce a tree: a parse error, a crash or a timeout."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


def _format_version(version: tuple[int, int, int]) -> str:
    return "v" + ".".join(str(part) for part in version)


@functools.cache
def _version(path: str) -> tuple[int, int, int] | None:
    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = _VERSION.search(proc.stdout)
    if proc.returncode != 0 or match is None:
        return None
    major, minor, patch = (int(group) for group in match.groups())
    return (major, minor, patch)


def check() -> str | None:
    """None when a usable shfmt is on PATH, else the notice explaining why not.

    The version is read once per shfmt binary, not once per script.
    """
    path = shutil.which("shfmt")
    if path is None:
        return "shfmt not found on PATH; using the regex rules."
    version = _version(path)
    if version is None:
        return "could not read the shfmt version; using the regex rules."
    if version < MIN_VERSION:
        return (
            f"shfmt {_format_version(version)} is older than "
            f"{_format_version(MIN_VERSION)}; using the regex rules."
        )
    return None


def parse_error(stderr: str) -> ShfmtError:
    """The ShfmtError for shfmt's stderr, with the line when shfmt gave one."""
    first = stderr.strip().splitlines()[0] if stderr.strip() else "shfmt failed"
    match = _ERROR_POSITION.match(first)
    line = int(match.group(1)) if match else None
    return ShfmtError(first, line)


def parse(text: str) -> Node:
    """The `File` node for `text`. Raises ShfmtError when there is no tree.

    Results are cached: embedded code (a `bash -c` string, a heredoc fed to a
    shell) is parsed through here too, and the same snippet often recurs.
    Callers must not mutate the returned tree.
    """
    return _parse_cached(text)


@functools.lru_cache(maxsize=512)
def _parse_cached(text: str) -> Node:
    try:
        proc = subprocess.run(
            ["shfmt", "--to-json", "-ln", "bash"],
            input=text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ShfmtError("shfmt timed out") from e
    except OSError as e:
        raise ShfmtError(f"shfmt could not run ({type(e).__name__})") from e
    if proc.returncode != 0:
        raise parse_error(proc.stderr)
    return decode(proc.stdout)


def decode(output: str) -> Node:
    """Validate and load shfmt's JSON. Raises ShfmtError on anything unexpected."""
    try:
        tree = json.loads(output)
    except json.JSONDecodeError as e:
        raise ShfmtError("shfmt printed invalid JSON") from e
    if not isinstance(tree, dict) or tree.get("Type") != "File":
        raise ShfmtError("shfmt printed an unexpected tree")
    if _has_integer_operator(tree):
        # A pre-v3.14 tree; the version check should have caught it.
        raise ShfmtError("shfmt encodes operators as integers (too old)")
    return tree


def _has_integer_operator(node: object) -> bool:
    if isinstance(node, dict):
        if isinstance(node.get("Op"), int):
            return True
        return any(_has_integer_operator(value) for value in node.values())
    if isinstance(node, list):
        return any(_has_integer_operator(item) for item in node)
    return False
