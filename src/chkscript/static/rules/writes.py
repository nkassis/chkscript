"""Rules on files the script writes and the permissions it sets."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator

from chkscript.static.commands import (
    Arg,
    Command,
    CommandModel,
    chmod_parts,
    parse_options,
)
from chkscript.static.rules.catalog import (
    AUTH_FILE,
    CRON_PATH,
    INIT_PATH,
    RC_FILE,
    REPO_PATH,
    SCHEDULER_PATH,
    SETID_MODE,
    SETID_SYSTEM_PATH,
    SYSTEM_PATH,
    SYSTEMD_PATH,
    USER_WRITABLE,
    WORLD_WRITABLE_MODE,
)
from chkscript.static.rules.common import Hit, matches, matching, write_targets

_AUTH_FILE = re.compile(AUTH_FILE)
_PERSISTENT = re.compile(rf"(?:{RC_FILE}|{SCHEDULER_PATH})")
_KINDS = (
    ("systemd", re.compile(SYSTEMD_PATH)),
    ("service", re.compile(INIT_PATH)),
    ("cron", re.compile(CRON_PATH)),
    ("rc", re.compile(RC_FILE)),
)
_WORLD_WRITABLE = re.compile(rf"{WORLD_WRITABLE_MODE}$")
_SETID = re.compile(rf"{SETID_MODE}$")
_USER_WRITABLE = re.compile(USER_WRITABLE)
_SETID_SYSTEM = re.compile(SETID_SYSTEM_PATH)
_SYSTEM = re.compile(SYSTEM_PATH)
# Covered by their own rules: auth files, persistence, repositories and keys.
_OTHER_RULES = re.compile(rf"(?:{AUTH_FILE}|{RC_FILE}|{SCHEDULER_PATH}|{REPO_PATH})")


def write_system_auth_file(model: CommandModel) -> Iterator[Hit]:
    for command in model.commands:
        if any(matches(t, _AUTH_FILE) for t in write_targets(command)):
            yield Hit("write-system-auth-file", command.line)


def _basename(path: str) -> str:
    return posixpath.basename(path.rstrip("/")) or path


def persistence_append(model: CommandModel) -> Iterator[Hit]:
    """Writes to a shell rc file, cron or systemd, and any crontab install."""
    for command in model.commands:
        paths = [matching(t, _PERSISTENT) for t in write_targets(command)]
        path = next((p for p in paths if p is not None), None)
        if path is not None:
            kind = next((k for k, p in _KINDS if p.match(path)), None)
            yield Hit("persistence-append", command.line, kind, _basename(path))
        elif command.name == "crontab":
            # `crontab FILE` and `... | crontab -` install a crontab;
            # `crontab -l` only lists one.
            if parse_options(command.args, short_value="u").operands:
                yield Hit("persistence-append", command.line, "cron", "crontab")


def _in_system_path(arg: Arg) -> bool:
    """Every value of `arg` is under a root-owned system directory."""
    if arg.values is None and not _SETID_SYSTEM.match(arg.text):
        return False
    return all(
        _SETID_SYSTEM.match(c) and not _USER_WRITABLE.match(c) for c in arg.candidates()
    )


def insecure_permissions(model: CommandModel) -> Iterator[Hit]:
    """World-writable modes anywhere and setuid/setgid outside a system path
    are `insecure-permissions`; setuid/setgid on files in a system path is
    `setuid-system`. A path that is not known to be a system path counts as
    user-writable."""
    for command in model.commands:
        if command.name == "chmod":
            mode, files = chmod_parts(command)
            if mode is None:
                continue
            if matches(mode, _WORLD_WRITABLE):
                yield Hit("insecure-permissions", command.line)
            elif matches(mode, _SETID):
                if files and all(_in_system_path(f) for f in files):
                    subject = files[0].literal or files[0].text
                    yield Hit("setuid-system", command.line, subject=subject)
                else:
                    yield Hit("insecure-permissions", command.line)
        elif command.name == "chown":
            operands = parse_options(command.args).operands
            if not operands:
                continue
            owner, files = operands[0], operands[1:]
            if any(c.startswith("root") for c in owner.candidates()) and any(
                matches(f, _USER_WRITABLE) for f in files
            ):
                yield Hit("insecure-permissions", command.line)


def _extract_dirs(command: Command) -> list[Arg]:
    """Where `tar -x -C DIR` and `unzip -d DIR` write."""
    if command.name == "tar":
        opts = parse_options(
            command.args, short_value="CfbT", long_value=frozenset({"--directory"})
        )
        directory = opts.value("-C", "--directory")
        return [directory] if directory is not None else []
    if command.name == "unzip":
        directory = parse_options(command.args, short_value="d").value("-d")
        return [directory] if directory is not None else []
    return []


def system_path_write(model: CommandModel) -> Iterator[Hit]:
    """A write, copy, move, install or extraction into /usr/local, /opt,
    /usr/bin, /usr/lib or /etc, other than files another rule reports."""
    for command in model.commands:
        for target in [*write_targets(command), *_extract_dirs(command)]:
            values = [
                c
                for c in target.possible()
                if _SYSTEM.match(c) and not _OTHER_RULES.match(c)
            ]
            if values:
                yield Hit("system-path-write", command.line, subject=values[0])
                break
