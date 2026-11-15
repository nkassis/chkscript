"""Rules on what single commands do: eval, rm -rf, disabling security, http."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chkscript.static.commands import DOWNLOADERS, Arg, CommandModel, parse_options
from chkscript.static.rules.catalog import SECURITY_SERVICES
from chkscript.static.rules.common import Hit

_SERVICE = re.compile(rf"(?:{SECURITY_SERVICES})\b")


def eval_dynamic(model: CommandModel) -> Iterator[Hit]:
    """eval of curl or wget output is `eval-remote`; of any other word built
    from a variable or command output, `eval-dynamic`."""
    for command in model.named("eval"):
        if any(arg.fetched for arg in command.args):
            yield Hit("eval-remote", command.line)
        elif any(arg.expanded for arg in command.args):
            yield Hit("eval-dynamic", command.line)


# An expansion followed by `/`: `$DIR/`, `${DIR}/x`, `$(pwd)/x`, `$1/`. A
# `${DIR:?...}` guard stops an empty value, so it does not count.
_SUBST_BODY = re.compile(r"\$\((?:[^()]|\([^()]*\))*\)")
_EXPANSION_THEN_SLASH = re.compile(
    r"(?:\$(?:\w+|[@*#?!$0-9])|\$\{(?![^}]*:\?)[^}]*\}|\$\([^)]*\)|`[^`]*`)/"
)


def _rm_operand(arg: Arg) -> str | None:
    """`rm-rf-unguarded`, `rm-rf-variable` or None for one rm -rf operand.

    Unguarded: a value known to be empty or `/` (with any trailing `/*`), or
    an unknown expansion that is unquoted or followed by a path. Quoted on its
    own (`"$TMP_DIR"`) or guarded (`"${DIR:?}/x"`) it is a capability: it
    deletes whatever the variable names, but cannot reach `/` by being empty.
    """
    if not arg.expanded:
        return None
    if arg.values is not None:
        if any(value.rstrip("*").strip("/") == "" for value in arg.values):
            return "rm-rf-unguarded"
        return None
    # What a `$(...)` runs is not the path: `$(mktemp -d "$d/tmp.X")`.
    text = _SUBST_BODY.sub("$()", arg.text)
    if arg.bare or arg.unquoted or _EXPANSION_THEN_SLASH.search(text):
        return "rm-rf-unguarded"
    return "rm-rf-variable"


def rm_rf_variable(model: CommandModel) -> Iterator[Hit]:
    for command in model.named("rm"):
        opts = parse_options(command.args)
        recursive = opts.has("-r", "-R", "--recursive")
        force = opts.has("-f", "--force")
        if not (recursive and force):
            continue
        found = [r for r in map(_rm_operand, opts.operands) if r is not None]
        if "rm-rf-unguarded" in found:
            yield Hit("rm-rf-unguarded", command.line)
        elif found:
            subject = next(
                a.text for a in opts.operands if _rm_operand(a) == "rm-rf-variable"
            )
            yield Hit("rm-rf-variable", command.line, subject=subject)


def runs_as_root(model: CommandModel) -> Iterator[Hit]:
    """A command run under sudo or doas (directly, through a wrapper function
    or `$SUDO`), and a root check that stops the script unless it is root."""
    for command in model.commands:
        if command.as_root:
            yield Hit("runs-as-root", command.line)
    for line in model.root_checks:
        yield Hit("runs-as-root", line)


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
