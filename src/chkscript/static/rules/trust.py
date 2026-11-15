"""Trust grants: package repositories (and their keys) and root-equivalent
groups. Both outlive the install and neither looks alarming in the script."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator

from chkscript.footprint import UNRESOLVED_HOST, url_host
from chkscript.static.commands import Arg, Command, CommandModel, parse_options
from chkscript.static.rules.catalog import (
    APT_SOURCE,
    GLOBAL_APT_KEY,
    ROOT_GROUPS,
    RPM_REPO,
)
from chkscript.static.rules.common import Hit, matching, write_targets

_APT_SOURCE = re.compile(APT_SOURCE)
_RPM_REPO = re.compile(RPM_REPO)
_GLOBAL_KEY = re.compile(GLOBAL_APT_KEY)
_GPG_OUTPUT = frozenset({"--output"})


def _name(path: str) -> str:
    return posixpath.basename(path.rstrip("/")) or path


def _repo(source: str) -> str:
    """A tool-added repository for the report: its host when it is a URL
    (`developer.download.nvidia.com`), else its name (`ppa:x/y`)."""
    if "://" in source:
        host = url_host(source)
        if host != UNRESOLVED_HOST:
            return host
    return _name(source)


def _content(command: Command, model: CommandModel) -> str:
    """Everything that may end up in the file `command` writes: its own
    words and heredocs, and those of the earlier stages of its pipeline."""
    senders = [command]
    if command.pipeline is not None:
        senders += [
            c
            for c in model.commands
            if c.pipeline == command.pipeline and c.stage < command.stage
        ]
    texts: list[str] = []
    for sender in senders:
        texts += [" ".join(a.possible()) for a in sender.argv]
        texts += [text for text, _ in sender.stdin_code()]
    return "\n".join(texts)


def _key_outputs(command: Command) -> list[Arg]:
    """Files a key is written to: write targets, and `gpg -o FILE`."""
    targets = write_targets(command)
    if command.name == "gpg":
        out = parse_options(command.args, "o", _GPG_OUTPUT).value("-o", "--output")
        if out is not None:
            targets.append(out)
    return targets


def _names(command: Command) -> set[str]:
    """The command's name, or the names its hinted values give it
    (`$PACKAGE_MANAGER config-manager` is dnf or yum)."""
    if command.name is not None:
        return {command.name}
    if not command.argv:
        return set()
    return {posixpath.basename(c) for c in command.argv[0].possible()}


def _adds_repo_by_tool(command: Command) -> str | None:
    """The repository a package tool is told to add, else None:
    `add-apt-repository X`, `dnf config-manager --add-repo X`,
    `yum-config-manager --add-repo X`, `zypper addrepo X`."""
    names = _names(command)
    args = command.args
    if "add-apt-repository" in names:
        operands = parse_options(args).operands
        return (operands[-1].literal or operands[-1].text) if operands else "repo"
    if names & {"dnf", "dnf5", "yum", "yum-config-manager"}:
        for i, arg in enumerate(args):
            text = arg.literal or arg.text
            if text.startswith("--add-repo="):
                return text.partition("=")[2]
            if text == "--add-repo":
                return args[i + 1].text if i + 1 < len(args) else "repo"
    if "zypper" in names:
        operands = parse_options(args).operands
        if operands and operands[0].literal in ("ar", "addrepo"):
            return operands[-1].text if len(operands) > 1 else "repo"
    return None


def package_repo_added(model: CommandModel) -> Iterator[Hit]:
    """A repository source written or added by a package tool, and any key
    trusted for every repository (`apt-key add`, `rpm --import`, a key in
    /etc/apt/trusted.gpg or trusted.gpg.d/). An apt source pinned with
    `signed-by=` is `scoped`; everything else is `global`."""
    for command in model.commands:
        targets = _key_outputs(command)
        apt = [p for t in targets if (p := matching(t, _APT_SOURCE)) is not None]
        rpm = [p for t in targets if (p := matching(t, _RPM_REPO)) is not None]
        keys = [p for t in targets if (p := matching(t, _GLOBAL_KEY)) is not None]
        if apt:
            scope = "scoped" if "signed-by=" in _content(command, model) else "global"
            yield Hit("package-repo-added", command.line, scope, _name(apt[0]))
        elif rpm:
            yield Hit("package-repo-added", command.line, "global", _name(rpm[0]))
        elif keys:
            yield Hit("package-repo-added", command.line, "global", _name(keys[0]))
        elif command.name == "apt-key":
            words = [a.literal for a in parse_options(command.args).operands]
            if "add" in words or "adv" in words:
                yield Hit("package-repo-added", command.line, "global", "apt-key")
        elif command.name == "rpm" and any(
            a.literal == "--import" for a in command.args
        ):
            yield Hit("package-repo-added", command.line, "global", "rpm --import")
        else:
            repo = _adds_repo_by_tool(command)
            if repo is not None:
                yield Hit("package-repo-added", command.line, "global", _repo(repo))


_USERMOD_VALUE = "cdefgGlpsuZkK"
_USERMOD_LONG = frozenset(
    {
        "--comment",
        "--home",
        "--expiredate",
        "--inactive",
        "--gid",
        "--groups",
        "--login",
        "--password",
        "--shell",
        "--uid",
        "--root",
        "--prefix",
    }
)


def _root_groups(arg: Arg | None) -> list[str]:
    if arg is None:
        return []
    groups = {g for c in arg.candidates() for g in c.split(",")}
    return [g for g in ROOT_GROUPS if g in groups]


def root_equivalent_group(model: CommandModel) -> Iterator[Hit]:
    """`usermod -aG`/`useradd -G`, `gpasswd -a USER GROUP` and
    `adduser`/`addgroup USER GROUP` with docker, lxd, libvirt or disk.
    `sudo` and `wheel` are a different rule (rogue-account, NIM-110)."""
    for command in model.commands:
        name = command.name
        groups: list[str] = []
        if name in ("usermod", "useradd"):
            opts = parse_options(command.args, _USERMOD_VALUE, _USERMOD_LONG)
            groups = _root_groups(opts.value("-G", "--groups"))
        elif name == "gpasswd":
            opts = parse_options(command.args, "adMA", frozenset({"--add"}))
            if opts.value("-a", "--add") is not None and opts.operands:
                groups = _root_groups(opts.operands[-1])
        elif name in ("adduser", "addgroup"):
            operands = parse_options(command.args).operands
            if len(operands) == 2:
                groups = _root_groups(operands[1])
        if groups:
            yield Hit("root-equivalent-group", command.line, subject=groups[0])
