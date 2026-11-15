"""Terminal and JSON output.

The terminal report reads: summary, unsafe findings, the `NEEDS` line, the
"What this script will do to your machine" section (capability findings as
plain lines, grouped by footprint group, ending with the absence line), then
lint, folded unless `-v`. Each capability line may carry a second line (the
model's assessment, from phase 3b); it is rendered from data, like the rest.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass

from chkscript.footprint import ABSENT_WORDS, UNRESOLVED_HOST
from chkscript.models import (
    ENTRY_FILE,
    AnalysisResult,
    Finding,
    Footprint,
    Group,
    Location,
    Severity,
)

# ANSI color codes
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

SECTION_TITLE = "What this script will do to your machine"
# Report order of the footprint groups; a capability with no group (a model
# finding) is listed under "other".
GROUP_ORDER: tuple[Group, ...] = (
    "root",
    "persistence",
    "system-write",
    "trust",
    "download",
    "other",
)
_GROUP_WIDTH = max(len(g) for g in GROUP_ORDER) + 2
_MAX_SUBJECTS = 3

# A finding's key, as merge.py keys them: (file, line, rule id).
FindingKey = tuple[str, int | None, str | None]


@dataclass(frozen=True)
class CapabilityLine:
    """One line of the capability section: the findings of one rule (and
    label) in one file, collapsed, or a single finding under `-v`.

    `detail` is the optional second line beneath it. Nothing sets it before
    phase 3b, which fills it with the model's assessment of the capability.
    """

    group: Group
    text: str
    findings: tuple[Finding, ...]
    detail: str | None = None

    @property
    def location(self) -> str:
        first = self.findings[0]
        where = _where(first)
        if len(self.findings) == 1:
            return f"({where})" if where else ""
        return f"({len(self.findings)} places, first at {where})"


def _use_color() -> bool:
    return sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if _use_color():
        return f"{code}{text}{_RESET}"
    return text


def _key(finding: Finding) -> FindingKey:
    return (finding.file, finding.line, finding.rule_id)


def _where(finding: Finding) -> str:
    """`line 42`, or `<file> line 42` outside the entry script."""
    line = "" if finding.line is None else f"line {finding.line}"
    if finding.file == ENTRY_FILE:
        return line or (finding.line_reference or "")
    where = f"{finding.file} {line}".strip()
    if finding.generated and finding.parent_line is not None:
        where += f", written by line {finding.parent_line}"
    return where


def _text(findings: list[Finding]) -> str:
    first = findings[0]
    label = first.label or first.description
    subjects: list[str] = []
    for f in findings:
        for subject in (f.subject or "").split(", "):
            if subject and subject not in subjects:
                subjects.append(subject)
    if not subjects:
        return label
    shown = ", ".join(subjects[:_MAX_SUBJECTS])
    if len(subjects) > _MAX_SUBJECTS:
        shown += f" and {len(subjects) - _MAX_SUBJECTS} more"
    return f"{label}: {shown}"


def capability_lines(
    findings: list[Finding],
    verbose: bool = False,
    details: Mapping[FindingKey, str] | None = None,
) -> list[CapabilityLine]:
    """Capability findings as report lines, in group order then first
    appearance. Findings of one rule and label in one file collapse into one
    line unless `verbose`. `details` maps a finding to its second line; a
    collapsed line takes the first one its findings have."""
    buckets: dict[tuple[object, ...], list[Finding]] = {}
    for finding in findings:
        if finding.category != "capability" and finding.group is None:
            continue
        if verbose:
            bucket: tuple[object, ...] = (len(buckets),)
        else:
            bucket = (finding.group, finding.file, finding.rule_id, finding.label)
            if finding.rule_id is None:
                bucket = (len(buckets),)
        buckets.setdefault(bucket, []).append(finding)
    lines: list[CapabilityLine] = []
    for members in buckets.values():
        detail = next(
            (details[_key(f)] for f in members if details and _key(f) in details),
            None,
        )
        lines.append(
            CapabilityLine(
                group=members[0].group or "other",
                text=_text(members),
                findings=tuple(members),
                detail=detail,
            )
        )
    return sorted(lines, key=lambda line: GROUP_ORDER.index(line.group))


def needs_line(footprint: Footprint) -> str:
    """`root · no persistent changes · downloads from 2 hosts`."""
    if footprint.privilege is None:
        privilege = "root not ruled out"
    else:
        privilege = footprint.privilege
    if footprint.persistence is None:
        persistence = "persistence not ruled out"
    elif footprint.persistence:
        persistence = "persistent changes"
    else:
        persistence = "no persistent changes"
    hosts = footprint.network_hosts
    if not hosts:
        downloads = "no downloads"
    else:
        noun = "host" if len(hosts) == 1 else "hosts"
        downloads = f"downloads from {len(hosts)} {noun}"
        unresolved = hosts.count(UNRESOLVED_HOST)
        if unresolved:
            downloads += f" ({unresolved} unresolved)"
    return " · ".join((privilege, persistence, downloads))


def _location_words(location: Location) -> str:
    where = f"line {location.line}" if location.line is not None else "unknown line"
    return where if location.file == ENTRY_FILE else f"{location.file} {where}"


def absence_lines(footprint: Footprint) -> list[str]:
    """How the capability section ends: what is absent, or why that cannot
    be said."""
    lines: list[str] = []
    if footprint.coverage == "reduced":
        lines.append("Not checked: static coverage reduced")
    if footprint.unresolved_at:
        lines.append(
            "Other changes possible: the script runs code chkscript could not "
            f"resolve ({_location_words(footprint.unresolved_at[0])})"
        )
    if footprint.unresolved_writes and footprint.coverage == "full":
        first = footprint.unresolved_writes[0]
        lines.append(
            "Other changes possible: the script writes to a path chkscript could "
            f"not resolve ({_location_words(first)})"
        )
    if not lines and footprint.absent:
        words = ", ".join(ABSENT_WORDS[g] for g in footprint.absent)
        lines.append(f"No other changes found: no {words}")
    return lines


def format_terminal(
    result: AnalysisResult,
    verbose: bool = False,
    details: Mapping[FindingKey, str] | None = None,
) -> str:
    lines: list[str] = []

    lines.append(_c(_GREEN + _BOLD, "== Summary =="))
    lines.append(result.summary)
    lines.append("")

    # Unsafe findings stay at the top, each with its snippet.
    for finding in result.findings:
        if finding.severity == Severity.UNSAFE:
            _format_finding(lines, finding, verbose)

    if result.footprint is not None:
        lines.append(_c(_BOLD, f"NEEDS   {needs_line(result.footprint)}"))
        lines.append("")

    capabilities = capability_lines(
        [f for f in result.findings if f.severity != Severity.UNSAFE],
        verbose,
        details,
    )
    if capabilities or result.footprint is not None:
        lines.append(_c(_BOLD, f"== {SECTION_TITLE} =="))
        for cap in capabilities:
            group = cap.group.ljust(_GROUP_WIDTH)
            lines.append(_c(_YELLOW, f"  {group}{cap.text} {cap.location}".rstrip()))
            if cap.detail:
                lines.append(f"  {' ' * _GROUP_WIDTH}{cap.detail}")
            if verbose:
                # One finding per line under -v: name its source and rule.
                first = cap.findings[0]
                snippet = f" {first.snippet.strip()}" if first.snippet else ""
                tag = _source_tag(first)
                lines.append(_c(_DIM, f"  {' ' * _GROUP_WIDTH}{tag}{snippet}"))
        if result.footprint is not None:
            for absence in absence_lines(result.footprint):
                lines.append(f"  {absence}")
        lines.append("")

    lint = [
        f
        for f in result.findings
        if f.severity != Severity.UNSAFE and f.category == "lint" and f.group is None
    ]
    if lint and verbose:
        lines.append(_c(_DIM, "-- Lint --"))
        for finding in lint:
            _format_finding(lines, finding, verbose)
    elif lint:
        noun = "finding" if len(lint) == 1 else "findings"
        lines.append(_c(_DIM, f"-- Lint: {len(lint)} {noun} (-v to show) --"))
        lines.append("")

    # Notes: the model's code-quality observations, not findings; -v only.
    if verbose and result.notes:
        lines.append(_c(_DIM, "-- Notes --"))
        for note in result.notes:
            lines.append(_c(_DIM, f"- {note}"))
        lines.append("")

    return "\n".join(lines)


def _location(finding: Finding) -> str:
    if finding.file != ENTRY_FILE:
        where = (
            finding.file if finding.line is None else f"{finding.file}:{finding.line}"
        )
        if finding.generated and finding.parent_line is not None:
            where += f", written by line {finding.parent_line}"
        return f" ({where})"
    if finding.line is not None:
        return f" (line {finding.line})"
    if finding.line_reference:
        return f" ({finding.line_reference})"
    return ""


def _source_tag(finding: Finding) -> str:
    sources = "+".join(finding.merged_from or [finding.source])
    rule = f" {finding.rule_id}" if finding.rule_id else ""
    return f"[{sources}{rule}]"


def _format_finding(lines: list[str], finding: Finding, verbose: bool) -> None:
    loc = _location(finding)
    tag = _source_tag(finding)

    if finding.severity == Severity.UNSAFE:
        prefix = _c(_RED + _BOLD, f"!! UNSAFE {tag}: {finding.description}{loc}")
    else:
        prefix = _c(_YELLOW, f"~~ WARNING {tag}: {finding.description}{loc}")

    lines.append(prefix)

    show_snippet = finding.snippet and (verbose or finding.severity == Severity.UNSAFE)
    if show_snippet:
        lines.append(f"   {finding.snippet}")

    lines.append("")


def format_json(result: AnalysisResult) -> str:
    data = {
        "summary": result.summary,
        "findings": [
            {
                "severity": finding.severity.name.lower(),
                "category": finding.category,
                "source": finding.source,
                "rule_id": finding.rule_id,
                "file": finding.file,
                "line": finding.line,
                "description": finding.description,
                "line_reference": finding.line_reference,
                "snippet": finding.snippet,
                "merged_from": finding.merged_from,
                "generated": finding.generated,
                "parent_line": finding.parent_line,
                "group": finding.group,
                "label": finding.label,
                "subject": finding.subject,
            }
            for finding in result.findings
        ],
        "notes": result.notes,
        "max_severity": result.max_severity.name.lower(),
        "mode": result.mode,
        "static_tools": result.static_tools,
        "footprint": (
            None if result.footprint is None else result.footprint.model_dump()
        ),
    }
    return json.dumps(data, indent=2)
