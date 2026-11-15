"""The syntax-tree engine: shfmt tree, command model, rules, findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from chkscript.models import Finding, ScriptBundle, Severity
from chkscript.preprocess import join_continuations
from chkscript.static import commands, regex_rules, rules, shfmt
from chkscript.static.commands import GeneratedFile


@dataclass
class EngineOutcome:
    findings: list[Finding] = field(default_factory=list)
    # Heredocs written to files the script runs, installs or chmods +x; the
    # static layer scans each as its own file.
    generated: list[GeneratedFile] = field(default_factory=list)
    # False when shfmt produced no tree; the regex rules then cover the file.
    parsed: bool = True


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
        _finding(bundle, hit.rule_id, hit.line, "shfmt") for hit in rules.run(model)
    ]
    # Embedded code shfmt could not parse (a `bash -c` string, a heredoc fed
    # to sh) still gets the floor: the regex rules, at the embedding line.
    for snippet in model.unparsed:
        for rule_id, line in regex_rules.matches(join_continuations(snippet.text)):
            findings.append(_finding(bundle, rule_id, snippet.line + line - 1, "regex"))
    return EngineOutcome(findings=findings, generated=model.generated)


def _finding(bundle: ScriptBundle, rule_id: str, line: int, source: str) -> Finding:
    return Finding(
        severity=Severity.UNSAFE,
        description=rules.MESSAGES[rule_id],
        snippet=bundle.line_text(line),
        source="shfmt" if source == "shfmt" else "regex",
        rule_id=rule_id,
        file=bundle.file,
        line=line,
    )
