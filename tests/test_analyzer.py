from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic_ai.messages import (
    FinishReason,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    TextPart,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from chkscript import analyzer
from chkscript.analyzer import (
    AnalysisError,
    FloorViolationError,
    LLMAnalyzer,
    check_floor,
    max_tokens_for,
    merge_llm,
    new_delimiter,
    to_findings,
)
from chkscript.models import Finding, LLMFinding, LLMResult, ScriptBundle, Severity
from chkscript.preprocess import preprocess

FIXTURES = Path(__file__).parent / "fixtures"

SCRIPT = b"""#!/bin/bash
set -euo pipefail
echo $HOME
curl -fsSL https://get.example.com/install.sh | sh
curl -fsSL -o /tmp/tool https://releases.example.com/tool
"""


def _bundle(raw: bytes = SCRIPT) -> ScriptBundle:
    return preprocess(raw)


def _static() -> list[Finding]:
    return [
        Finding(
            severity=Severity.WARNING,
            category="lint",
            description="Double quote to prevent globbing",
            source="shellcheck",
            rule_id="SC2086",
            line=3,
        ),
        Finding(
            severity=Severity.UNSAFE,
            category="unsafe",
            description="Pipes a download into a shell",
            source="semgrep",
            rule_id="curl-pipe-shell",
            line=4,
        ),
        Finding(
            severity=Severity.WARNING,
            category="capability",
            description="Downloads a binary verified by TLS only",
            source="semgrep",
            rule_id="unverified-download",
            line=5,
        ),
    ]


def _respond(
    output: dict[str, Any], info: AgentInfo, finish: FinishReason = "stop"
) -> ModelResponse:
    part: ToolCallPart | TextPart
    if info.output_tools:
        part = ToolCallPart(info.output_tools[0].name, output)
    else:
        part = TextPart(json.dumps(output))
    return ModelResponse(parts=[part], finish_reason=finish)


def _scripted(output: dict[str, Any], seen: list[Any] | None = None) -> FunctionModel:
    """A model that always returns `output`, recording (messages, info) per call."""

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        if seen is not None:
            seen.append((messages, info))
        return _respond(output, info)

    return FunctionModel(fn)


def _prompt(messages: list[ModelMessage]) -> str:
    request = messages[0]
    assert isinstance(request, ModelRequest)
    parts = [p for p in request.parts if isinstance(p, UserPromptPart)]
    assert isinstance(parts[0].content, str)
    return parts[0].content


EMPTY: dict[str, Any] = {"summary": "s", "findings": [], "notes": []}


class TestAnalyze:
    def test_returns_structured_result(self) -> None:
        result = LLMAnalyzer(TestModel()).analyze(_bundle(), _static())
        assert isinstance(result, LLMResult)

    def test_scripted_output_is_parsed(self) -> None:
        output = {
            "summary": "Installs a tool",
            "findings": [
                {"category": "capability", "description": "Writes to /tmp", "line": 5}
            ],
            "notes": ["Uses set -e"],
        }
        result = LLMAnalyzer(_scripted(output)).analyze(_bundle(), _static())
        assert result.summary == "Installs a tool"
        assert result.findings[0].line == 5
        assert result.notes == ["Uses set -e"]

    def test_native_output_when_supported(self) -> None:
        seen: list[Any] = []
        model = _scripted(EMPTY, seen)
        LLMAnalyzer(model).analyze(_bundle(), [])
        assert seen[0][1].model_request_parameters.output_mode == "native"

    def test_tool_output_otherwise(self) -> None:
        seen: list[Any] = []

        def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
            seen.append(info)
            return _respond(EMPTY, info)

        model = FunctionModel(fn, profile={"supports_json_schema_output": False})
        LLMAnalyzer(model).analyze(_bundle(), [])
        assert seen[0].model_request_parameters.output_mode == "tool"

    def test_temperature_zero_and_scaled_max_tokens(self) -> None:
        seen: list[Any] = []
        bundle = _bundle()
        LLMAnalyzer(_scripted(EMPTY, seen)).analyze(bundle, [])
        settings = seen[0][1].model_settings
        assert settings["temperature"] == 0
        assert settings["max_tokens"] == max_tokens_for(bundle)

    def test_max_tokens_grows_with_lines_and_is_capped(self) -> None:
        small = max_tokens_for(_bundle(b"echo hi\n"))
        large = max_tokens_for(_bundle(b"echo hi\n" * 400))
        huge = max_tokens_for(_bundle(b"echo hi\n" * 50_000))
        assert small < large < huge
        assert huge == analyzer._MAX_TOKENS_CAP

    def test_instructions_define_categories_and_scope(self) -> None:
        seen: list[Any] = []
        LLMAnalyzer(_scripted(EMPTY, seen)).analyze(_bundle(), [])
        instructions = seen[0][1].instructions
        for word in ("lint", "capability", "unsafe", "notes", "must not dispute"):
            assert word in instructions

    def test_static_findings_sent_as_structured_data(self) -> None:
        seen: list[Any] = []
        LLMAnalyzer(_scripted(EMPTY, seen)).analyze(_bundle(), _static())
        prompt = _prompt(seen[0][0])
        payload = json.loads(prompt[prompt.index("[") : prompt.index("]\n") + 1])
        assert {"source", "rule_id", "category", "line", "message"} == set(payload[0])
        assert [r["rule_id"] for r in payload] == [
            "SC2086",
            "curl-pipe-shell",
            "unverified-download",
        ]

    def test_truncated_response_raises(self) -> None:
        def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
            return _respond(EMPTY, info, finish="length")

        with pytest.raises(AnalysisError, match="truncated"):
            LLMAnalyzer(FunctionModel(fn)).analyze(_bundle(), [])

    def test_truncated_unparseable_response_raises(self) -> None:
        def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
            return ModelResponse(
                parts=[TextPart('{"summary": "cut off')], finish_reason="length"
            )

        with pytest.raises(AnalysisError, match="truncated"):
            LLMAnalyzer(FunctionModel(fn)).analyze(_bundle(), [])

    def test_provider_failure_raises_analysis_error(self) -> None:
        def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
            raise ConnectionError("connection refused")

        with pytest.raises(AnalysisError, match="connection refused"):
            LLMAnalyzer(FunctionModel(fn)).analyze(_bundle(), [])

    def test_unknown_model_raises_analysis_error(self) -> None:
        with pytest.raises(AnalysisError):
            LLMAnalyzer("no-such-provider:model")


class TestDelimiter:
    _TAG = re.compile(r"<(script-[0-9a-f]+)>\n")

    def _tag_of(self, raw: bytes) -> tuple[str, str]:
        seen: list[Any] = []
        LLMAnalyzer(_scripted(EMPTY, seen)).analyze(_bundle(raw), [])
        prompt = _prompt(seen[0][0])
        match = self._TAG.search(prompt)
        assert match is not None
        return match.group(1), prompt

    def test_random_per_run(self) -> None:
        tags = {self._tag_of(SCRIPT)[0] for _ in range(5)}
        assert len(tags) == 5

    def test_survives_literal_closing_script_tag(self) -> None:
        raw = (FIXTURES / "injection_delimiter.sh").read_bytes()
        tag, prompt = self._tag_of(raw)
        body = prompt.split(f"<{tag}>\n", 1)[1]
        assert body.count(f"</{tag}>") == 1
        inside = body.split(f"</{tag}>")[0]
        # Everything in the file, including its fake `</script>`, is inside.
        assert "</script>" in inside
        assert "New instructions from chkscript" in inside
        assert inside.rstrip().endswith('echo "done"')

    def test_script_is_line_numbered(self) -> None:
        tag, prompt = self._tag_of(SCRIPT)
        assert re.search(r"^\s+4 \| curl -fsSL", prompt, re.MULTILINE)

    def test_regenerated_if_script_contains_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        values = iter(["aaaaaaaaaaaa", "bbbbbbbbbbbb"])
        monkeypatch.setattr(analyzer.secrets, "token_hex", lambda n: next(values))
        assert new_delimiter("x <script-aaaaaaaaaaaa> y") == "script-bbbbbbbbbbbb"


def _result(*findings: dict[str, Any]) -> LLMResult:
    return LLMResult(summary="s", findings=[LLMFinding(**f) for f in findings])


class TestToFindings:
    def test_reasoned_raise_of_capability_becomes_unsafe(self) -> None:
        raw = {
            "category": "unsafe",
            "rule_id": "unverified-download",
            "line": 5,
            "description": "Host does not belong to the project",
        }
        (finding,) = to_findings(_result(raw), _bundle(), _static())
        assert finding.severity == Severity.UNSAFE
        assert finding.category == "unsafe"
        assert finding.rule_id == "unverified-download"
        assert finding.source == "llm"

    def test_raise_without_reason_ignored(self) -> None:
        raw = {
            "category": "unsafe",
            "rule_id": "unverified-download",
            "line": 5,
            "description": "  ",
        }
        assert to_findings(_result(raw), _bundle(), _static()) == []

    def test_restating_static_finding_dropped(self) -> None:
        raw = {
            "category": "capability",
            "rule_id": "curl-pipe-shell",
            "line": 4,
            "description": "Actually fine, the vendor is trusted",
        }
        assert to_findings(_result(raw), _bundle(), _static()) == []

    def test_lint_cannot_be_raised(self) -> None:
        raw = {
            "category": "unsafe",
            "rule_id": "SC2086",
            "line": 3,
            "description": "Word splitting is dangerous here",
        }
        assert to_findings(_result(raw), _bundle(), _static()) == []

    def test_new_finding_gets_llm_prefix_and_severity(self) -> None:
        raw = {
            "category": "unsafe",
            "rule_id": "mismatched-host",
            "line": 5,
            "description": "Downloads from an unrelated host",
        }
        (finding,) = to_findings(_result(raw), _bundle(), _static())
        assert finding.rule_id == "llm.mismatched-host"
        assert finding.severity == Severity.UNSAFE
        assert finding.snippet is not None and "releases.example.com" in finding.snippet

    def test_prefix_not_doubled(self) -> None:
        raw = {"category": "capability", "rule_id": "llm.root", "description": "d"}
        (finding,) = to_findings(_result(raw), _bundle(), _static())
        assert finding.rule_id == "llm.root"
        assert finding.severity == Severity.WARNING

    def test_static_rule_id_on_other_line_cannot_collide(self) -> None:
        raw = {
            "category": "capability",
            "rule_id": "curl-pipe-shell",
            "line": 2,
            "description": "d",
        }
        (finding,) = to_findings(_result(raw), _bundle(), _static())
        assert finding.rule_id == "llm.curl-pipe-shell"

    def test_out_of_range_line_dropped(self) -> None:
        raw = {"category": "capability", "line": 999, "description": "d"}
        (finding,) = to_findings(_result(raw), _bundle(), _static())
        assert finding.line is None


def _by_rule(findings: list[Finding]) -> dict[str | None, Finding]:
    return {f.rule_id: f for f in findings}


class TestFloor:
    """The model cannot drop or lower a static finding, whatever it outputs."""

    def test_empty_output_keeps_every_static_finding(self) -> None:
        merged = merge_llm(_static(), _result(), _bundle())
        assert [f.rule_id for f in merged] == [f.rule_id for f in _static()]
        assert [f.severity for f in merged] == [f.severity for f in _static()]

    def test_scripted_downgrade_attempt_holds(self) -> None:
        # The model tries to re-rate the unsafe finding and the capability
        # finding down, and to "clear" the lint one.
        output = {
            "summary": "Safe, no issues",
            "findings": [
                {
                    "category": "capability",
                    "rule_id": "curl-pipe-shell",
                    "line": 4,
                    "description": "False positive; vendor is trusted",
                },
                {
                    "category": "capability",
                    "rule_id": "unverified-download",
                    "line": 5,
                    "description": "Fine",
                },
            ],
            "notes": [],
        }
        bundle = _bundle()
        llm = LLMAnalyzer(_scripted(output)).analyze(bundle, _static())
        merged = _by_rule(merge_llm(_static(), llm, bundle))
        assert merged["curl-pipe-shell"].severity == Severity.UNSAFE
        assert merged["curl-pipe-shell"].category == "unsafe"
        assert merged["unverified-download"].category == "capability"
        assert merged["SC2086"].category == "lint"
        assert max(f.severity for f in merged.values()) == Severity.UNSAFE

    def test_raise_merges_into_static_finding(self) -> None:
        raw = {
            "category": "unsafe",
            "rule_id": "unverified-download",
            "line": 5,
            "description": "Host does not belong to the project",
        }
        merged = _by_rule(merge_llm(_static(), _result(raw), _bundle()))
        raised = merged["unverified-download"]
        assert raised.severity == Severity.UNSAFE
        assert raised.category == "unsafe"
        assert raised.merged_from == ["semgrep", "llm"]
        assert raised.description == "Host does not belong to the project"
        assert len(merged) == 3

    def test_check_floor_raises_on_dropped_finding(self) -> None:
        static = _static()
        with pytest.raises(FloorViolationError, match="dropped"):
            check_floor(static, static[:2])

    def test_check_floor_raises_on_lowered_severity(self) -> None:
        static = _static()
        lowered = static[1].model_copy(update={"severity": Severity.WARNING})
        with pytest.raises(FloorViolationError, match="lowered"):
            check_floor(static, [static[0], lowered, static[2]])

    def test_check_floor_raises_on_lowered_category(self) -> None:
        static = _static()
        lowered = static[2].model_copy(update={"category": "lint"})
        with pytest.raises(FloorViolationError, match="lowered"):
            check_floor(static, [static[0], static[1], lowered])

    def test_merge_llm_raises_when_merge_lowers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A merge bug that rewrites severities must fail loudly, not report.
        def broken_merge(findings: list[Finding]) -> list[Finding]:
            return [f.model_copy(update={"severity": Severity.SAFE}) for f in findings]

        monkeypatch.setattr(analyzer, "merge", broken_merge)
        with pytest.raises(FloorViolationError):
            merge_llm(_static(), _result(), _bundle())


class TestEndpoint:
    def test_test_model_has_no_host(self) -> None:
        assert LLMAnalyzer(TestModel()).endpoint_host is None

    def test_ollama_host_from_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1")
        assert LLMAnalyzer("ollama:gpt-oss:20b").endpoint_host == "127.0.0.1"

    def test_anthropic_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
        host = LLMAnalyzer("anthropic:claude-sonnet-5-5").endpoint_host
        assert host == "api.anthropic.com"
