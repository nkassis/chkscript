"""The footprint summary: what a script does to the machine, in one line.

Computed by chkscript from the merged findings and the download hosts the
static layer recorded, never by the model, so `--static-only` has it too. A
negative ("user", "no persistent changes", an absent group) is a claim, so it
is stated only when the scan can back it: full static coverage and no code
chkscript could not resolve. A quieter report must never be what an evasive
script earns.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from chkscript.models import Finding, Footprint, Group, Location

UNRESOLVED_HOST = "(unresolved)"

# Findings whose code chkscript never saw: an eval of a variable or of
# downloaded text, and anything that feeds a download (or decoded data) to a
# shell or to a command it could not resolve.
UNRESOLVED_RULES = frozenset(
    {"eval-dynamic", "eval-remote", "curl-pipe-shell", "decode-to-shell"}
)

# The groups whose absence the report states, and how it says each.
ABSENT_GROUPS: tuple[Group, ...] = ("persistence", "system-write", "trust")
ABSENT_WORDS: dict[Group, str] = {
    "persistence": "services, cron jobs, shell config",
    "system-write": "system file writes",
    "trust": "repos or group changes",
}

_HOST = re.compile(r"^(?:[A-Za-z][\w+.-]*://)?(?:[^@/?#]*@)?([^/:?#\s]+)")


def url_host(url: str) -> str:
    """The host of a URL (scheme optional), or UNRESOLVED_HOST when it is not
    written out: built from a variable, or not a URL at all."""
    match = _HOST.match(url.strip("\"'"))
    if match is None:
        return UNRESOLVED_HOST
    host = match.group(1).lower()
    if re.search(r"[$`{}()\[\]*]", host) or "." not in host and host != "localhost":
        return UNRESOLVED_HOST
    return host


def sorted_hosts(hosts: Iterable[str]) -> list[str]:
    """Distinct hosts, sorted, with UNRESOLVED_HOST (if any) last."""
    unique = set(hosts)
    return sorted(unique - {UNRESOLVED_HOST}) + (
        [UNRESOLVED_HOST] if UNRESOLVED_HOST in unique else []
    )


def compute(
    findings: list[Finding],
    hosts: Iterable[str],
    coverage_full: bool,
    unresolved_writes: Iterable[Location] = (),
) -> Footprint:
    groups = {f.group for f in findings if f.group is not None}
    unresolved = [
        Location(file=f.file, line=f.line)
        for f in findings
        if f.rule_id in UNRESOLVED_RULES
    ]
    blind_writes = list(unresolved_writes)
    backed = coverage_full and not unresolved
    # A write to an unknown path may be a unit file or a shell rc file.
    writes_backed = backed and not blind_writes
    root = "root" in groups
    persistent = "persistence" in groups
    return Footprint(
        privilege="root" if root else ("user" if backed else None),
        persistence=True if persistent else (False if writes_backed else None),
        network_hosts=sorted_hosts(hosts),
        coverage="full" if coverage_full else "reduced",
        unresolved_at=unresolved,
        unresolved_writes=blind_writes,
        absent=(
            [g for g in ABSENT_GROUPS if g not in groups] if writes_backed else None
        ),
    )
