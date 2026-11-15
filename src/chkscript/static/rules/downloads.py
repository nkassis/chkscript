"""unverified-download: judged per downloaded file.

A file is tied to a later path by the same text or value, the same basename,
an archive or checksum suffix (`$exe.zip` and `$exe`, `t.sha256` and `t`), or a
`mv`/`cp` between them. A download is verified when a sha256sum, shasum,
`gpg --verify` or cosign command names a path tied to it. A check-mode
verifier (`sha256sum -c`) whose sums file cannot be tied to any download
counts for every download.

The finding lands on each chmod that makes an unverified download executable.
"""

from __future__ import annotations

from collections.abc import Iterator

from chkscript.static.commands import (
    Arg,
    Command,
    CommandModel,
    Download,
    adds_execute,
    chmod_parts,
    parse_options,
    path_names,
)
from chkscript.static.rules.common import Hit

_GPG_LONG_VALUE = frozenset({"--keyring", "--homedir", "--output", "--status-fd"})
_COSIGN_LONG_VALUE = frozenset(
    {
        "--key",
        "--signature",
        "--certificate",
        "--certificate-identity",
        "--certificate-oidc-issuer",
        "--certificate-chain",
        "--bundle",
        "--rekor-url",
    }
)


def _verifier(command: Command) -> tuple[bool, list[Arg]] | None:
    """(check mode, files named) when `command` verifies files, else None."""
    name = command.name
    if name in ("sha256sum", "shasum"):
        opts = parse_options(command.args, short_value="a", long_value=frozenset())
        return opts.has("-c", "--check"), list(opts.operands)
    if name == "gpg" and any(a.literal == "--verify" for a in command.args):
        opts = parse_options(command.args, short_value="o", long_value=_GPG_LONG_VALUE)
        return False, list(opts.operands)
    if name == "cosign":
        opts = parse_options(command.args, long_value=_COSIGN_LONG_VALUE)
        return False, list(opts.operands[1:])
    return None


def _names_with_aliases(download: Download, model: CommandModel) -> set[str]:
    """The download's path names, plus every mv/cp destination of it."""
    path = download.path
    names = path_names(path) if path is not None else set()
    changed = True
    while changed:
        changed = False
        for command in model.named("mv", "cp"):
            operands = parse_options(command.args, short_value="tS").operands
            if len(operands) < 2:
                continue
            *sources, destination = operands
            if any(path_names(s) & names for s in sources):
                new = path_names(destination) - names
                if new:
                    names |= new
                    changed = True
    return names


def unverified_download(model: CommandModel) -> Iterator[Hit]:
    downloads = [d for d in model.downloads if d.path is not None]
    if not downloads:
        return
    groups = [_names_with_aliases(d, model) for d in downloads]
    verified = [False] * len(downloads)
    for command in model.commands:
        verifier = _verifier(command)
        if verifier is None:
            continue
        check, files = verifier
        tied_any = False
        for i, names in enumerate(groups):
            if any(path_names(f) & names for f in files):
                verified[i] = True
                tied_any = True
        if check and not tied_any:
            verified = [True] * len(downloads)

    for command in model.named("chmod"):
        mode, files = chmod_parts(command)
        if mode is None or not adds_execute(mode):
            continue
        for file in files:
            names = path_names(file)
            if any(
                names & g and not ok for g, ok in zip(groups, verified, strict=True)
            ):
                yield Hit("unverified-download", command.line)
                break
