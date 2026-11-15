"""Helpers shared by the rules: hits, and what a command writes to."""

from __future__ import annotations

import re
from typing import NamedTuple

from chkscript.static.commands import COPIERS, Arg, Command, parse_options


class Hit(NamedTuple):
    rule_id: str
    line: int


_COPY_SHORT_VALUE = "mogStT"
_COPY_LONG_VALUE = frozenset({"--target-directory", "--suffix", "--mode", "--owner"})


def write_targets(command: Command) -> list[Arg]:
    """Files the command writes: output redirects, tee files, the destination
    of cp/mv/install/ln, sed -i files and dd's `of=`."""
    targets = [r.target for r in command.redirects if r.writes and r.target]
    name = command.name
    if name == "tee":
        targets += parse_options(command.args).operands
    elif name in COPIERS:
        opts = parse_options(command.args, _COPY_SHORT_VALUE, _COPY_LONG_VALUE)
        directory = opts.value("-t", "--target-directory")
        if directory is not None:
            targets.append(directory)
        elif len(opts.operands) >= 2:
            targets.append(opts.operands[-1])
    elif name == "sed":
        opts = parse_options(command.args, "ef", frozenset({"--expression"}))
        if any(flag.startswith("-i") or flag == "--in-place" for flag, _ in opts.flags):
            scripted = opts.has("-e", "-f", "--expression")
            targets += opts.operands if scripted else opts.operands[1:]
    elif name == "dd":
        for arg in command.args:
            if arg.text.startswith("of="):
                targets.append(_after(arg, "of="))
    return targets


def _after(arg: Arg, prefix: str) -> Arg:
    values = None
    if arg.values is not None:
        values = frozenset(v[len(prefix) :] for v in arg.values)
    return Arg(arg.text[len(prefix) :], values, arg.expanded, line=arg.line)


def matches(arg: Arg, pattern: re.Pattern[str]) -> bool:
    """Whether any value of `arg` (or its text, when unknown) starts with
    `pattern`. A partly known word such as `/etc/sudoers.d/$NAME` still
    matches on its literal prefix."""
    return any(pattern.match(candidate) for candidate in arg.candidates())
