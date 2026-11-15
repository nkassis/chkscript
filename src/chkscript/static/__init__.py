"""The static layer: deterministic findings the model cannot remove or downgrade."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from chkscript import redact
from chkscript.footprint import sorted_hosts
from chkscript.models import ENTRY_FILE, Finding, Location, ScriptBundle, StaticTool
from chkscript.preprocess import ScriptTooLargeError, preprocess
from chkscript.static import engine, regex_rules, shellcheck, shfmt
from chkscript.static.commands import GeneratedFile
from chkscript.static.merge import merge

# A generated file can itself write and run a generated file; past this many
# levels the rest is left to the parent's findings.
MAX_GENERATED_DEPTH = 3


class StaticResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(default_factory=list)
    tools: list[StaticTool] = Field(default_factory=list)
    # One-line messages for stderr: missing tools, reduced coverage.
    notices: list[str] = Field(default_factory=list)
    # Hosts the script (or a generated child) downloads from, for the
    # footprint; footprint.UNRESOLVED_HOST for one that is not a constant.
    hosts: list[str] = Field(default_factory=list)
    # False when the regex rules stood in for the tree on any file or snippet.
    coverage_full: bool = True
    # Writes to a path chkscript could not resolve (engine.unresolved_writes).
    unresolved_writes: list[Location] = Field(default_factory=list)


def run_static(bundle: ScriptBundle) -> StaticResult:
    result = _scan(bundle, depth=0)
    ordered = sorted(
        result.findings,
        key=lambda f: (f.file != ENTRY_FILE, f.generated, f.line is None, f.line or 0),
    )
    return result.model_copy(update={"findings": merge(ordered)})


def _scan(bundle: ScriptBundle, depth: int) -> StaticResult:
    findings: list[Finding] = []
    tools: list[StaticTool] = []
    notices: list[str] = []

    if shellcheck.available():
        try:
            findings += shellcheck.run(bundle)
            tools.append("shellcheck")
        except shellcheck.ShellcheckError as e:
            notices.append(f"shellcheck failed ({e}); warning tier skipped.")
    else:
        notices.append("shellcheck not found on PATH; warning tier skipped.")

    needs_regex = True
    coverage_full = True
    hosts: list[str] = []
    unresolved: list[Location] = []
    generated: list[GeneratedFile] = []
    unusable = shfmt.check()
    if unusable is None:
        outcome = engine.scan(bundle)
        findings += outcome.findings
        generated = outcome.generated
        hosts += outcome.hosts
        coverage_full = not outcome.unparsed
        unresolved += [
            Location(file=bundle.file, line=n) for n in outcome.unresolved_writes
        ]
        tools.append("shfmt")
        needs_regex = not outcome.parsed
        if needs_regex:
            notices.append("shfmt could not parse the script; regex rules ran.")
    else:
        notices.append(unusable)

    if needs_regex:
        findings += regex_rules.run(bundle)
        hosts += regex_rules.download_hosts(bundle)
        coverage_full = False
        tools.append("regex")
    if tools == ["regex"]:
        notices.append("Only the regex rules ran (no shellcheck, no shfmt).")

    # Not a rule over commands: detected in preprocessing, so every mode has it.
    findings += redact.secret_findings(bundle)

    if depth < MAX_GENERATED_DEPTH:
        for child in generated:
            child_result = _scan_generated(child, depth)
            if child_result is not None:
                findings += child_result.findings
                notices += [n for n in child_result.notices if n not in notices]
                hosts += child_result.hosts
                coverage_full = coverage_full and child_result.coverage_full
                unresolved += child_result.unresolved_writes
    return StaticResult(
        findings=findings,
        tools=tools,
        notices=notices,
        hosts=sorted_hosts(hosts),
        coverage_full=coverage_full,
        unresolved_writes=unresolved,
    )


def _scan_generated(child: GeneratedFile, depth: int) -> StaticResult | None:
    """Scan a generated file as its own script; its findings point at it."""
    try:
        bundle = preprocess(child.text.encode("utf-8"), file=child.label)
    except ScriptTooLargeError:
        return None  # cannot happen: the parent passed the same size check
    result = _scan(bundle, depth + 1)
    findings = [
        (
            f
            if f.generated
            else f.model_copy(update={"generated": True, "parent_line": child.line})
        )
        for f in result.findings
    ]
    return result.model_copy(update={"findings": findings})
