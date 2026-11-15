"""Rules on files the script writes and the permissions it sets."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chkscript.static.commands import CommandModel, chmod_parts, parse_options
from chkscript.static.rules.catalog import (
    AUTH_FILE,
    INSECURE_MODE,
    RC_FILE,
    SCHEDULER_PATH,
    USER_WRITABLE,
)
from chkscript.static.rules.common import Hit, matches, write_targets

_AUTH_FILE = re.compile(AUTH_FILE)
_PERSISTENT = re.compile(rf"(?:{RC_FILE}|{SCHEDULER_PATH})")
_INSECURE_MODE = re.compile(rf"{INSECURE_MODE}$")
_USER_WRITABLE = re.compile(USER_WRITABLE)


def write_system_auth_file(model: CommandModel) -> Iterator[Hit]:
    for command in model.commands:
        if any(matches(t, _AUTH_FILE) for t in write_targets(command)):
            yield Hit("write-system-auth-file", command.line)


def persistence_append(model: CommandModel) -> Iterator[Hit]:
    """Writes to a shell rc file, cron or systemd, and any crontab install."""
    for command in model.commands:
        if any(matches(t, _PERSISTENT) for t in write_targets(command)):
            yield Hit("persistence-append", command.line)
        elif command.name == "crontab":
            # `crontab FILE` and `... | crontab -` install a crontab;
            # `crontab -l` only lists one.
            if parse_options(command.args, short_value="u").operands:
                yield Hit("persistence-append", command.line)


def insecure_permissions(model: CommandModel) -> Iterator[Hit]:
    for command in model.commands:
        if command.name == "chmod":
            mode, _ = chmod_parts(command)
            if mode is not None and matches(mode, _INSECURE_MODE):
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
