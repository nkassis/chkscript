"""Rules on what single commands do: eval, rm -rf, disabling security, http."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chkscript.static.commands import DOWNLOADERS, Arg, CommandModel, parse_options
from chkscript.static.rules.catalog import SECURITY_SERVICES
from chkscript.static.rules.common import Hit

_SERVICE = re.compile(rf"(?:{SECURITY_SERVICES})\b")


def eval_dynamic(model: CommandModel) -> Iterator[Hit]:
    """eval of any word built from a variable or command output."""
    for command in model.named("eval"):
        if any(arg.expanded for arg in command.args):
            yield Hit("eval-dynamic", command.line)


def _dangerous_rm_operand(arg: Arg) -> bool:
    """An operand built from an expansion that is unknown, or that can be
    empty or `/` (with any trailing `/*`)."""
    if not arg.expanded:
        return False
    if arg.values is None:
        return True
    return any(value.rstrip("*").strip("/") == "" for value in arg.values)


def rm_rf_variable(model: CommandModel) -> Iterator[Hit]:
    for command in model.named("rm"):
        opts = parse_options(command.args)
        recursive = opts.has("-r", "-R", "--recursive")
        force = opts.has("-f", "--force")
        if recursive and force and any(map(_dangerous_rm_operand, opts.operands)):
            yield Hit("rm-rf-variable", command.line)


def disable_security(model: CommandModel) -> Iterator[Hit]:
    for command in model.commands:
        operands = parse_options(command.args).operands
        words = [arg.literal for arg in operands]
        if command.name == "setenforce" and words[:1] == ["0"]:
            yield Hit("disable-security", command.line)
        elif command.name == "ufw" and "disable" in words:
            yield Hit("disable-security", command.line)
        elif command.name == "systemctl" and "disable" in words:
            services = operands[words.index("disable") + 1 :]
            if any(_SERVICE.match(c) for arg in services for c in arg.candidates()):
                yield Hit("disable-security", command.line)


def http_download(model: CommandModel) -> Iterator[Hit]:
    for download in model.downloads:
        if download.command.name not in DOWNLOADERS:
            continue
        for url in download.urls:
            if any(c.lower().startswith("http://") for c in url.candidates()):
                yield Hit("http-download", download.line)
                break
