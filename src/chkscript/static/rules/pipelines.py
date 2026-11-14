"""Rules over pipelines: downloaded or decoded data fed to a shell."""

from __future__ import annotations

from collections.abc import Callable, Iterator

from chkscript.static.commands import (
    DOWNLOADERS,
    SHELLS,
    Command,
    CommandModel,
    parse_options,
)
from chkscript.static.rules.common import Hit


def runs_stdin_as_shell(command: Command) -> bool:
    """A pipe receiver that may run its input as code.

    An unknown command is judged as the dangerous case, and so is a bare
    `sudo`/`doas` whose command could not be resolved.
    """
    if not command.argv:
        return False
    if command.argv[0].values is None:
        return True
    return command.name in SHELLS or command.name in ("sudo", "doas")


def _piped_to_shell(
    model: CommandModel, sender: Callable[[Command], bool], rule_id: str
) -> Iterator[Hit]:
    for command in model.commands:
        if command.pipeline is None or not sender(command):
            continue
        if any(runs_stdin_as_shell(c) for c in model.later_stages(command)):
            yield Hit(rule_id, command.line)


def curl_pipe_shell(model: CommandModel) -> Iterator[Hit]:
    return _piped_to_shell(model, lambda c: c.name in DOWNLOADERS, "curl-pipe-shell")


def is_decoder(command: Command) -> bool:
    """base64 -d, xxd -r, openssl enc -d, gunzip -c."""
    name = command.name
    opts = parse_options(command.args)
    if name == "base64":
        return opts.has("-d", "-D", "--decode")
    if name == "xxd":
        return opts.has("-r", "--revert")
    if name == "openssl":
        return (
            bool(opts.operands) and opts.operands[0].literal == "enc" and opts.has("-d")
        )
    if name == "gunzip":
        return opts.has("-c", "--stdout", "--to-stdout")
    return False


def decode_to_shell(model: CommandModel) -> Iterator[Hit]:
    return _piped_to_shell(model, is_decoder, "decode-to-shell")
