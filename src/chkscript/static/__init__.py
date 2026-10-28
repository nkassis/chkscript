"""The static layer: deterministic findings the model cannot remove or downgrade."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from chkscript.models import Finding, ScriptBundle, StaticTool
from chkscript.static import regex_rules, semgrep, shellcheck
from chkscript.static.merge import merge


class StaticResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(default_factory=list)
    tools: list[StaticTool] = Field(default_factory=list)
    # One-line messages for stderr: missing tools, reduced coverage.
    notices: list[str] = Field(default_factory=list)


def run_static(bundle: ScriptBundle) -> StaticResult:
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
    if semgrep.available():
        outcome = semgrep.run(bundle)
        findings += outcome.findings
        tools.append("semgrep")
        needs_regex = not outcome.complete
        if needs_regex:
            notices.append("Semgrep did not cover the whole file; regex rules ran too.")
    else:
        notices.append("semgrep not found on PATH; using the regex rules.")

    if needs_regex:
        findings += regex_rules.run(bundle)
        tools.append("regex")
    if tools == ["regex"]:
        notices.append("Only the regex rules ran (no shellcheck, no semgrep).")

    ordered = sorted(findings, key=lambda f: (f.line is None, f.line or 0))
    return StaticResult(findings=merge(ordered), tools=tools, notices=notices)
