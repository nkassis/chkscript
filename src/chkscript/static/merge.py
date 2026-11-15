"""Merge findings from every source. Merging can raise severity, never lower it."""

from __future__ import annotations

from collections.abc import Iterable

from chkscript.models import CATEGORY_RANK, Finding, Source

_Key = tuple[str, int | None, str]


def _sources(finding: Finding) -> list[Source]:
    return list(finding.merged_from) or [finding.source]


def merge(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse findings sharing `(file, line, rule_id)` into one.

    The merged finding takes the description of the most severe input (the first
    one on a tie), the highest severity, the most severe category, and every
    source in `merged_from`; a capability's group, label and subject are kept.
    Findings with no `rule_id` (free-form model findings) are never merged.
    Order of first appearance is kept.
    """
    merged: list[Finding] = []
    index: dict[_Key, int] = {}
    for finding in findings:
        sources = _sources(finding)
        if finding.rule_id is None:
            merged.append(finding.model_copy(update={"merged_from": sources}))
            continue
        key = (finding.file, finding.line, finding.rule_id)
        if key not in index:
            index[key] = len(merged)
            merged.append(finding.model_copy(update={"merged_from": sources}))
            continue
        existing = merged[index[key]]
        winner = finding if finding.severity > existing.severity else existing
        combined = list(existing.merged_from)
        combined += [s for s in sources if s not in combined]
        category = max(
            (existing.category, finding.category), key=CATEGORY_RANK.__getitem__
        )
        merged[index[key]] = winner.model_copy(
            update={
                "severity": max(existing.severity, finding.severity),
                "category": category,
                "merged_from": combined,
                # A capability's group, label and subject survive a raise.
                "group": existing.group or finding.group,
                "label": existing.label or finding.label,
                "subject": existing.subject or finding.subject,
            }
        )
    return merged
