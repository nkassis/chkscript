from __future__ import annotations

import json

from chkscript.formatter import (
    SECTION_TITLE,
    absence_lines,
    capability_lines,
    format_json,
    format_terminal,
    needs_line,
)
from chkscript.models import (
    ENTRY_FILE,
    AnalysisResult,
    Finding,
    Footprint,
    Group,
    Location,
    Severity,
)


def _safe_result() -> AnalysisResult:
    return AnalysisResult(
        summary="Simple echo script",
        findings=[],
        notes=["No issues"],
    )


def _unsafe_result() -> AnalysisResult:
    return AnalysisResult(
        summary="Dangerous installer",
        findings=[
            Finding(
                severity=Severity.UNSAFE,
                description="Pipes curl to bash",
                line_reference="line 3",
                snippet="curl -fsSL ... | bash",
            ),
            Finding(
                severity=Severity.WARNING,
                description="No set -e",
                line_reference="line 1",
                snippet=None,
            ),
        ],
        notes=["Targets Ubuntu/Debian"],
    )


class TestFormatTerminal:
    def test_safe_output(self) -> None:
        output = format_terminal(_safe_result())
        assert "Summary" in output
        assert "Simple echo script" in output
        assert "No issues" not in output

    def test_notes_shown_with_verbose(self) -> None:
        assert "No issues" in format_terminal(_safe_result(), verbose=True)

    def test_unsafe_output(self) -> None:
        output = format_terminal(_unsafe_result())
        assert "UNSAFE" in output
        assert "Pipes curl to bash" in output
        assert "curl -fsSL ... | bash" in output

    def test_capability_without_a_group_is_listed_under_other(self) -> None:
        # A warning with no category is a capability (a model finding).
        output = format_terminal(_unsafe_result())
        assert "  other         No set -e (line 1)" in output

    def test_verbose_shows_warning_snippets(self) -> None:
        result = AnalysisResult(
            summary="test",
            findings=[
                Finding(
                    severity=Severity.WARNING,
                    description="issue",
                    snippet="some code",
                ),
            ],
        )
        default = format_terminal(result, verbose=False)
        verbose = format_terminal(result, verbose=True)
        assert "some code" not in default
        assert "some code" in verbose

    def test_unsafe_snippet_shown_by_default(self) -> None:
        result = AnalysisResult(
            summary="test",
            findings=[
                Finding(
                    severity=Severity.UNSAFE,
                    description="bad",
                    snippet="rm -rf /",
                ),
            ],
        )
        output = format_terminal(result, verbose=False)
        assert "rm -rf /" in output


class TestFormatJson:
    def test_valid_json(self) -> None:
        output = format_json(_safe_result())
        data = json.loads(output)
        assert data["summary"] == "Simple echo script"
        assert data["max_severity"] == "safe"

    def test_findings_in_json(self) -> None:
        output = format_json(_unsafe_result())
        data = json.loads(output)
        assert len(data["findings"]) == 2
        assert data["findings"][0]["severity"] == "unsafe"
        assert data["findings"][1]["severity"] == "warning"
        assert data["max_severity"] == "unsafe"

    def test_json_has_all_fields(self) -> None:
        output = format_json(_unsafe_result())
        data = json.loads(output)
        finding = data["findings"][0]
        assert "severity" in finding
        assert "description" in finding
        assert "line_reference" in finding
        assert "snippet" in finding


def _static_result() -> AnalysisResult:
    return AnalysisResult(
        summary="Static analysis only.",
        findings=[
            Finding(
                severity=Severity.UNSAFE,
                description="Piped into a shell",
                snippet="curl https://x | sh",
                source="shfmt",
                rule_id="curl-pipe-shell",
                line=4,
                merged_from=["shfmt", "regex"],
            ),
            Finding(
                severity=Severity.WARNING,
                category="lint",
                description="shfmt could not parse this file",
                source="chkscript",
                rule_id="parse-failure",
            ),
        ],
        mode="static-only",
        static_tools=["shellcheck", "shfmt", "regex"],
    )


class TestSourceAttribution:
    def test_terminal_shows_sources_rule_and_line(self) -> None:
        output = format_terminal(_static_result())
        assert "[shfmt+regex curl-pipe-shell]" in output
        assert "(line 4)" in output
        assert "[chkscript parse-failure]" not in output  # lint, folded
        assert "-- Lint: 1 finding (-v to show) --" in output
        assert "[chkscript parse-failure]" in format_terminal(
            _static_result(), verbose=True
        )

    def test_terminal_tags_llm_finding(self) -> None:
        output = format_terminal(_unsafe_result())
        assert "[llm]" in output
        assert "(line 3)" in output

    def test_json_finding_fields(self) -> None:
        data = json.loads(format_json(_static_result()))
        finding = data["findings"][0]
        assert finding["source"] == "shfmt"
        assert finding["category"] == "unsafe"
        assert finding["rule_id"] == "curl-pipe-shell"
        assert finding["file"] == "<entry>"
        assert finding["line"] == 4
        assert finding["merged_from"] == ["shfmt", "regex"]

    def test_json_mode_and_static_tools(self) -> None:
        data = json.loads(format_json(_static_result()))
        assert data["mode"] == "static-only"
        assert data["static_tools"] == ["shellcheck", "shfmt", "regex"]
        assert data["findings"][0]["generated"] is False
        assert data["findings"][0]["parent_line"] is None


def _generated_result() -> AnalysisResult:
    return AnalysisResult(
        summary="Static analysis only.",
        findings=[
            Finding(
                severity=Severity.UNSAFE,
                description="rm -rf on a variable",
                snippet='rm -rf "$1"',
                source="shfmt",
                rule_id="rm-rf-unguarded",
                file="$KILLALL_K3S_SH",
                line=75,
                generated=True,
                parent_line=803,
            )
        ],
        mode="static-only",
    )


class TestGeneratedFiles:
    def test_terminal_names_the_file_and_the_writing_line(self) -> None:
        output = format_terminal(_generated_result())
        assert "($KILLALL_K3S_SH:75, written by line 803)" in output

    def test_json_marks_generated(self) -> None:
        [finding] = json.loads(format_json(_generated_result()))["findings"]
        assert finding["file"] == "$KILLALL_K3S_SH"
        assert finding["generated"] is True
        assert finding["parent_line"] == 803


def _capability(
    rule_id: str,
    line: int,
    group: Group,
    label: str,
    subject: str | None = None,
    file: str = ENTRY_FILE,
) -> Finding:
    return Finding(
        severity=Severity.WARNING,
        category="capability",
        description=f"{rule_id} message",
        snippet=f"code at {line}",
        source="shfmt",
        rule_id=rule_id,
        file=file,
        line=line,
        group=group,
        label=label,
        subject=subject,
    )


def _footprint(**overrides: object) -> Footprint:
    fields: dict[str, object] = {
        "privilege": "root",
        "persistence": True,
        "network_hosts": ["get.k3s.io", "github.com"],
        "coverage": "full",
        "unresolved_at": [],
        "absent": ["trust"],
    }
    fields.update(overrides)
    return Footprint.model_validate(fields)


def _capability_result(footprint: Footprint | None = None) -> AnalysisResult:
    return AnalysisResult(
        summary="Static analysis only.",
        findings=[
            _capability("runs-as-root", 30, "root", "Runs commands as root"),
            _capability("runs-as-root", 41, "root", "Runs commands as root"),
            _capability(
                "unverified-download",
                545,
                "download",
                "Downloads binaries verified only by TLS",
                "k3s",
            ),
            _capability(
                "persistence-append",
                860,
                "persistence",
                "Installs a systemd service",
                "k3s.service",
            ),
            Finding(
                severity=Severity.WARNING,
                category="lint",
                description="Double quote to prevent globbing",
                source="shellcheck",
                rule_id="SC2086",
                line=12,
            ),
        ],
        mode="static-only",
        footprint=footprint or _footprint(),
    )


class TestCapabilitySection:
    def test_lines_are_grouped_and_collapsed(self) -> None:
        output = format_terminal(_capability_result())
        section = output[output.index(SECTION_TITLE) :]
        assert section.splitlines()[1:4] == [
            "  root          Runs commands as root (2 places, first at line 30)",
            "  persistence   Installs a systemd service: k3s.service (line 860)",
            "  download      Downloads binaries verified only by TLS: k3s (line 545)",
        ]

    def test_verbose_expands_collapsed_lines(self) -> None:
        output = format_terminal(_capability_result(), verbose=True)
        assert "Runs commands as root (line 30)" in output
        assert "Runs commands as root (line 41)" in output
        assert "[shfmt runs-as-root] code at 30" in output

    def test_unsafe_stays_on_top_and_lint_is_folded(self) -> None:
        result = _capability_result()
        result.findings.insert(
            0,
            Finding(
                severity=Severity.UNSAFE,
                description="Piped into a shell",
                source="shfmt",
                rule_id="curl-pipe-shell",
                line=7,
            ),
        )
        output = format_terminal(result)
        assert output.index("!! UNSAFE") < output.index("NEEDS")
        assert output.index("NEEDS") < output.index(SECTION_TITLE)
        assert "Double quote" not in output
        assert output.rstrip().endswith("-- Lint: 1 finding (-v to show) --")
        assert "Double quote" in format_terminal(result, verbose=True)

    def test_second_line_is_rendered_from_data(self) -> None:
        # Phase 3b fills `details` with the model's assessment; the formatter
        # only renders what it is given.
        details = {(ENTRY_FILE, 860, "persistence-append"): "Needed: a server"}
        output = format_terminal(_capability_result(), details=details)
        lines = output.splitlines()
        i = lines.index(
            "  persistence   Installs a systemd service: k3s.service (line 860)"
        )
        assert lines[i + 1] == f"  {' ' * 14}Needed: a server"
        assert "Needed" not in format_terminal(_capability_result())

    def test_a_collapsed_line_takes_the_first_detail(self) -> None:
        details = {(ENTRY_FILE, 41, "runs-as-root"): "Unexplained: why root"}
        [root, *_] = capability_lines(_capability_result().findings, details=details)
        assert root.detail == "Unexplained: why root"
        assert len(root.findings) == 2

    def test_child_file_is_named(self) -> None:
        finding = _capability(
            "persistence-append",
            4,
            "persistence",
            "Installs a cron job",
            file="/usr/local/bin/k3s-killall.sh",
        )
        [line] = capability_lines([finding])
        assert line.location == "(/usr/local/bin/k3s-killall.sh line 4)"

    def test_many_subjects_are_shortened(self) -> None:
        findings = [
            _capability("system-path-write", n, "system-write", "Writes", f"/opt/{n}")
            for n in range(1, 6)
        ]
        [line] = capability_lines(findings)
        assert line.text == "Writes: /opt/1, /opt/2, /opt/3 and 2 more"


class TestNeedsLine:
    def test_root_persistent_hosts(self) -> None:
        assert needs_line(_footprint()) == (
            "root · persistent changes · downloads from 2 hosts"
        )

    def test_user_no_persistence_no_downloads(self) -> None:
        footprint = _footprint(privilege="user", persistence=False, network_hosts=[])
        assert needs_line(footprint) == "user · no persistent changes · no downloads"

    def test_unbacked_negatives_are_not_ruled_out(self) -> None:
        footprint = _footprint(
            privilege=None, persistence=None, network_hosts=["(unresolved)"]
        )
        assert needs_line(footprint) == (
            "root not ruled out · persistence not ruled out · "
            "downloads from 1 host (1 unresolved)"
        )


class TestAbsenceLine:
    def test_full_coverage_names_the_absent_groups(self) -> None:
        footprint = _footprint(absent=["persistence", "system-write", "trust"])
        assert absence_lines(footprint) == [
            "No other changes found: no services, cron jobs, shell config, "
            "system file writes, repos or group changes"
        ]

    def test_nothing_absent_says_nothing(self) -> None:
        assert absence_lines(_footprint(absent=[])) == []

    def test_regex_fallback(self) -> None:
        footprint = _footprint(coverage="reduced", absent=None)
        assert absence_lines(footprint) == ["Not checked: static coverage reduced"]

    def test_unresolved_dynamic_code(self) -> None:
        footprint = _footprint(
            unresolved_at=[Location(line=1203), Location(line=1300)], absent=None
        )
        assert absence_lines(footprint) == [
            "Other changes possible: the script runs code chkscript could not "
            "resolve (line 1203)"
        ]

    def test_both_reduced_and_unresolved(self) -> None:
        footprint = _footprint(
            coverage="reduced",
            unresolved_at=[Location(file="$KILLALL_K3S_SH", line=75)],
            absent=None,
        )
        assert absence_lines(footprint) == [
            "Not checked: static coverage reduced",
            "Other changes possible: the script runs code chkscript could not "
            "resolve ($KILLALL_K3S_SH line 75)",
        ]

    def test_the_section_ends_with_the_absence_line(self) -> None:
        output = format_terminal(_capability_result())
        section = output[output.index(SECTION_TITLE) :].split("\n\n")[0]
        assert section.splitlines()[-1] == (
            "  No other changes found: no repos or group changes"
        )


class TestFootprintJson:
    def test_finding_group_label_subject(self) -> None:
        data = json.loads(format_json(_capability_result()))
        unit = data["findings"][3]
        assert (unit["category"], unit["group"]) == ("capability", "persistence")
        assert (unit["label"], unit["subject"]) == (
            "Installs a systemd service",
            "k3s.service",
        )
        assert data["findings"][4]["group"] is None

    def test_top_level_footprint(self) -> None:
        data = json.loads(format_json(_capability_result()))
        assert data["footprint"] == {
            "privilege": "root",
            "persistence": True,
            "network_hosts": ["get.k3s.io", "github.com"],
            "coverage": "full",
            "unresolved_at": [],
            "unresolved_writes": [],
            "absent": ["trust"],
        }

    def test_no_footprint_is_null(self) -> None:
        assert json.loads(format_json(_safe_result()))["footprint"] is None
