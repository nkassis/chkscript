"""The syntax-tree engine: shfmt tree, command model, rules, findings."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from chkscript.footprint import UNRESOLVED_HOST, url_host
from chkscript.models import Finding, ScriptBundle, Severity
from chkscript.preprocess import join_continuations
from chkscript.static import commands, regex_rules, rules, shfmt
from chkscript.static.commands import (
    Arg,
    Command,
    CommandModel,
    GeneratedFile,
    parse_options,
)
from chkscript.static.rules.common import write_targets


@dataclass
class EngineOutcome:
    findings: list[Finding] = field(default_factory=list)
    # Heredocs written to files the script runs, installs or chmods +x; the
    # static layer scans each as its own file.
    generated: list[GeneratedFile] = field(default_factory=list)
    # False when shfmt produced no tree; the regex rules then cover the file.
    parsed: bool = True
    # The host of every URL the script downloads from (footprint.UNRESOLVED_HOST
    # for one that is not a constant), and whether embedded code had to be
    # left to the regex rules.
    hosts: list[str] = field(default_factory=list)
    unparsed: bool = False
    # Lines that write to a path chkscript could not resolve at all
    # (`>> "$PROFILE"`): it may be a service or shell rc file.
    unresolved_writes: list[int] = field(default_factory=list)


def parse_failure(bundle: ScriptBundle, error: shfmt.ShfmtError) -> Finding:
    return Finding(
        severity=Severity.WARNING,
        category="lint",
        description=shfmt.PARSE_FAILURE_MESSAGE,
        source="chkscript",
        rule_id=shfmt.PARSE_FAILURE_RULE,
        file=bundle.file,
        line=error.line,
    )


def scan(bundle: ScriptBundle) -> EngineOutcome:
    try:
        tree = shfmt.parse(bundle.text)
    except shfmt.ShfmtError as e:
        return EngineOutcome(findings=[parse_failure(bundle, e)], parsed=False)
    model = commands.build(tree, bundle.text, bundle.file, shfmt.parse)
    findings = [
        rules.finding(bundle, hit.rule_id, hit.line, "shfmt", hit.variant, hit.subject)
        for hit in rules.run(model)
    ]
    # Embedded code shfmt could not parse (a `bash -c` string, a heredoc fed
    # to sh) still gets the floor: the regex rules, at the embedding line.
    for snippet in model.unparsed:
        for hit in regex_rules.matches(join_continuations(snippet.text)):
            line = snippet.line + hit.line - 1
            findings.append(
                rules.finding(
                    bundle, hit.rule_id, line, "regex", hit.variant, hit.subject
                )
            )
    return EngineOutcome(
        findings=findings,
        generated=model.generated,
        hosts=download_hosts(model),
        unparsed=bool(model.unparsed),
        unresolved_writes=unresolved_writes(model),
    )


def download_hosts(model: CommandModel) -> list[str]:
    """Hosts of the URLs each curl or wget fetches. A download whose URL
    cannot be read (`curl "$@"`) counts as one unresolved host."""
    hosts: list[str] = []
    for download in model.downloads:
        if not download.urls:
            if any(
                a.splat or (a.values is None and not a.is_flag)
                for a in download.command.args
            ):
                hosts.append(UNRESOLVED_HOST)
            continue
        for url in download.urls:
            hosts += _hosts(url)
    for command in model.commands:
        if _is_git(command):
            hosts += [h for url in _git_urls(command) for h in _hosts(url)]
    return hosts


def _hosts(url: Arg) -> list[str]:
    hosts = [url_host(c) for c in url.possible()]
    if url.values is None:
        # A hint is what the URL usually is, not what it must be.
        hosts.append(UNRESOLVED_HOST)
    return hosts


_REMOTE_URL_KEY = re.compile(r"^remote\.[^.]+\.url$")
_GIT_URL = re.compile(r"^(?:[a-z][\w+.-]*://|[\w.-]+@[\w.-]+:)")


def _is_git(command: Command) -> bool:
    """git, also when named by a variable whose hint is a git path
    (Homebrew's `"${USABLE_GIT}"`)."""
    if not command.argv:
        return False
    return any(posixpath.basename(c) == "git" for c in command.argv[0].possible())


def _git_urls(command: Command) -> list[Arg]:
    """The remote a `git clone`, `git remote add|set-url`, `git config
    remote.<name>.url`, `git fetch` or `git pull` reads from: a URL operand,
    or for clone, remote and config an operand that cannot be read."""
    operands = parse_options(command.args).operands
    sub = operands[0].literal if operands else None
    rest = list(operands[1:])
    if sub == "remote" and rest and rest[0].literal in ("add", "set-url"):
        rest = rest[-1:]
    elif sub == "config" and rest and _REMOTE_URL_KEY.match(rest[0].literal or ""):
        rest = rest[1:2]
    elif sub not in ("clone", "fetch", "pull"):
        return []
    urls = [a for a in rest if any(_GIT_URL.match(c) for c in a.possible())]
    if not urls and sub in ("clone", "remote", "config"):
        urls = [a for a in rest[:1] if a.values is None]
    return urls


def _resolved(path: str) -> bool:
    """A path whose location is written out: absolute, under the home
    directory, or relative. One that starts with an unknown variable is not."""
    home = path.startswith(("$HOME", "${HOME}"))
    return home or not path.startswith(("$", "`"))


def unresolved_writes(model: CommandModel) -> list[int]:
    """Lines whose write target (redirect, tee, cp/mv/install/ln destination,
    sed -i, dd, download output) has no resolved candidate or hint."""
    lines: list[int] = []
    for command in model.commands:
        targets = write_targets(command)
        if any(not any(map(_resolved, t.possible())) for t in targets):
            lines.append(command.line)
    for download in model.downloads:
        path = download.path
        if path is not None and not any(map(_resolved, path.possible())):
            lines.append(download.line)
    return sorted(set(lines))
