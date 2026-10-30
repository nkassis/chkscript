from __future__ import annotations

import json

from chkscript.formatter import format_json, format_terminal
from chkscript.models import AnalysisResult, Finding, Severity


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
        assert "No issues" in output

    def test_unsafe_output(self) -> None:
        output = format_terminal(_unsafe_result())
        assert "UNSAFE" in output
        assert "Pipes curl to bash" in output
        assert "curl -fsSL ... | bash" in output

    def test_warning_output(self) -> None:
        output = format_terminal(_unsafe_result())
        assert "WARNING" in output
        assert "No set -e" in output

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
                source="semgrep",
                rule_id="curl-pipe-shell",
                line=4,
                merged_from=["semgrep", "regex"],
            ),
            Finding(
                severity=Severity.WARNING,
                description="Semgrep could not fully parse this file",
                source="chkscript",
                rule_id="semgrep-parse-error",
            ),
        ],
        mode="static-only",
        static_tools=["shellcheck", "semgrep", "regex"],
    )


class TestSourceAttribution:
    def test_terminal_shows_sources_rule_and_line(self) -> None:
        output = format_terminal(_static_result())
        assert "[semgrep+regex curl-pipe-shell]" in output
        assert "(line 4)" in output
        assert "[chkscript semgrep-parse-error]" in output

    def test_terminal_tags_llm_finding(self) -> None:
        output = format_terminal(_unsafe_result())
        assert "[llm]" in output
        assert "(line 3)" in output

    def test_json_finding_fields(self) -> None:
        data = json.loads(format_json(_static_result()))
        finding = data["findings"][0]
        assert finding["source"] == "semgrep"
        assert finding["category"] == "unsafe"
        assert finding["rule_id"] == "curl-pipe-shell"
        assert finding["file"] == "<entry>"
        assert finding["line"] == 4
        assert finding["merged_from"] == ["semgrep", "regex"]

    def test_json_mode_and_static_tools(self) -> None:
        data = json.loads(format_json(_static_result()))
        assert data["mode"] == "static-only"
        assert data["static_tools"] == ["shellcheck", "semgrep", "regex"]
