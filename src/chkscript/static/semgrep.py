"""Semgrep adapter: the unsafe tier, using the rules shipped in chkscript/rules."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from chkscript.models import Finding, ScriptBundle, Severity

PARSE_ERROR_RULE = "semgrep-parse-error"
FAILURE_RULE = "semgrep-failure"
PARSE_ERROR_MESSAGE = (
    "Semgrep could not fully parse this file; static coverage reduced."
)
FAILURE_MESSAGE = "Semgrep failed on this file; static coverage reduced."

# Semgrep's names for errors that mean "this file did not fully parse".
_PARSE_ERROR_TYPES = frozenset(
    {"PartialParsing", "Syntax error", "Lexical error", "Other syntax error"}
)
_TIMEOUT_SECONDS = 120


class SemgrepOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(default_factory=list)
    # False when Semgrep did not cover the whole file; the regex rules then run.
    complete: bool = True


def available() -> bool:
    return shutil.which("semgrep") is not None


def run(bundle: ScriptBundle) -> SemgrepOutcome:
    rules = resources.files("chkscript") / "rules"
    with tempfile.TemporaryDirectory() as tmp, resources.as_file(rules) as rules_dir:
        target = Path(tmp) / "script.sh"
        target.write_text(bundle.text, encoding="utf-8")
        try:
            proc = subprocess.run(
                [
                    "semgrep",
                    "scan",
                    "--config",
                    str(rules_dir),
                    "--json",
                    "--metrics=off",
                    "--quiet",
                    "--disable-version-check",
                    str(target),
                ],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return _failed(bundle, FAILURE_RULE, FAILURE_MESSAGE)
    return parse_output(proc.stdout, bundle)


def _failed(bundle: ScriptBundle, rule_id: str, message: str) -> SemgrepOutcome:
    return SemgrepOutcome(
        findings=[_coverage_warning(bundle, rule_id, message)], complete=False
    )


def _coverage_warning(bundle: ScriptBundle, rule_id: str, message: str) -> Finding:
    return Finding(
        severity=Severity.WARNING,
        description=message,
        source="chkscript",
        rule_id=rule_id,
        file=bundle.file,
    )


def _error_type(error: dict[str, Any]) -> str:
    kind = error.get("type")
    if isinstance(kind, list) and kind:
        kind = kind[0]
    return kind if isinstance(kind, str) else ""


def parse_output(output: str, bundle: ScriptBundle) -> SemgrepOutcome:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return _failed(bundle, FAILURE_RULE, FAILURE_MESSAGE)
    if not isinstance(data, dict):
        return _failed(bundle, FAILURE_RULE, FAILURE_MESSAGE)

    findings = []
    for result in data.get("results", []):
        line = int(result["start"]["line"])
        findings.append(
            Finding(
                severity=Severity.UNSAFE,
                description=result["extra"]["message"],
                snippet=bundle.line_text(line),
                source="semgrep",
                # With --config DIR, check_id is prefixed by the rule file's path.
                rule_id=result["check_id"].rsplit(".", 1)[-1],
                file=bundle.file,
                line=line,
            )
        )

    errors = data.get("errors", [])
    if not errors:
        return SemgrepOutcome(findings=findings)
    if any(_error_type(e) in _PARSE_ERROR_TYPES for e in errors):
        warning = _coverage_warning(bundle, PARSE_ERROR_RULE, PARSE_ERROR_MESSAGE)
    else:
        warning = _coverage_warning(bundle, FAILURE_RULE, FAILURE_MESSAGE)
    return SemgrepOutcome(findings=[*findings, warning], complete=False)
