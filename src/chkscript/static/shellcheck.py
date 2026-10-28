"""shellcheck adapter: the warning tier. Nothing from here is ever `unsafe`."""

from __future__ import annotations

import json
import shutil
import subprocess

from chkscript.models import Finding, ScriptBundle, Severity

# Codes that are noise on install scripts. Each is recorded in docs/decisions.md.
SUPPRESSED: frozenset[str] = frozenset(
    {
        "SC1090",  # can't follow a non-constant `source`: about our environment
        "SC1091",  # sourced file not found: about our environment
    }
)

_TIMEOUT_SECONDS = 60


class ShellcheckError(Exception):
    pass


def available() -> bool:
    return shutil.which("shellcheck") is not None


def run(bundle: ScriptBundle) -> list[Finding]:
    try:
        proc = subprocess.run(
            ["shellcheck", "-f", "json", "-"],
            input=bundle.text,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ShellcheckError(str(e)) from e
    # Exit 1 means "findings"; anything above that is a shellcheck failure.
    if proc.returncode not in (0, 1):
        raise ShellcheckError(f"exit {proc.returncode}: {proc.stderr.strip()}")
    return parse_output(proc.stdout, bundle)


def parse_output(output: str, bundle: ScriptBundle) -> list[Finding]:
    try:
        comments = json.loads(output)
    except json.JSONDecodeError as e:
        raise ShellcheckError(f"unreadable JSON output: {e}") from e
    findings = []
    for comment in comments:
        rule_id = f"SC{comment['code']}"
        if rule_id in SUPPRESSED:
            continue
        line = int(comment["line"])
        findings.append(
            Finding(
                severity=Severity.WARNING,
                description=comment["message"],
                snippet=bundle.line_text(line),
                source="shellcheck",
                rule_id=rule_id,
                file=bundle.file,
                line=line,
            )
        )
    return findings
