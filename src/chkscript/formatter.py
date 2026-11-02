from __future__ import annotations

import json
import sys

from chkscript.models import AnalysisResult, Finding, Severity

# ANSI color codes
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _use_color() -> bool:
    return sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if _use_color():
        return f"{code}{text}{_RESET}"
    return text


def format_terminal(result: AnalysisResult, verbose: bool = False) -> str:
    lines: list[str] = []

    # Summary
    lines.append(_c(_GREEN + _BOLD, "== Summary =="))
    lines.append(result.summary)
    lines.append("")

    # Findings
    for finding in result.findings:
        _format_finding(lines, finding, verbose)

    # Notes: the model's code-quality observations, not findings; -v only.
    if verbose and result.notes:
        lines.append(_c(_DIM, "-- Notes --"))
        for note in result.notes:
            lines.append(_c(_DIM, f"- {note}"))
        lines.append("")

    return "\n".join(lines)


def _location(finding: Finding) -> str:
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
            }
            for finding in result.findings
        ],
        "notes": result.notes,
        "max_severity": result.max_severity.name.lower(),
        "mode": result.mode,
        "static_tools": result.static_tools,
    }
    return json.dumps(data, indent=2)
