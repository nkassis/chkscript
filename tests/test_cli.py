from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pytest_mock import MockerFixture

from chkscript.analyzer import FloorViolationError, LLMAnalyzer
from chkscript.cli import main
from chkscript.config import DEFAULT_HOSTED_MODEL, DEFAULT_LOCAL_MODEL
from chkscript.models import LLMFinding, LLMResult, Severity
from chkscript.static import StaticResult

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def set_api_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # patch.dict restores all of os.environ, including keys load_config exports.
    with patch.dict(os.environ):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("CHKSCRIPT_MODEL", raising=False)
        monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
        yield


@pytest.fixture(autouse=True)
def no_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never probe a real Ollama; tests opt in by patching this back."""
    monkeypatch.setattr("chkscript.config.ollama_reachable", lambda: False)


def _mock_result(severity: Severity = Severity.SAFE, **kwargs: object) -> LLMResult:
    defaults: dict[str, Any] = dict(summary="Test result", findings=[], notes=[])
    defaults.update(kwargs)
    if severity == Severity.UNSAFE:
        defaults["findings"] = [LLMFinding(category="unsafe", description="Bad thing")]
    elif severity == Severity.WARNING:
        defaults["findings"] = [
            LLMFinding(category="capability", description="Minor thing")
        ]
    return LLMResult(**defaults)


def _model_returning(result: LLMResult) -> FunctionModel:
    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        return ModelResponse(parts=[TextPart(result.model_dump_json())])

    return FunctionModel(fn)


def _failing_model() -> FunctionModel:
    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        raise ConnectionError("connection refused")

    return FunctionModel(fn)


def _use_model(mocker: MockerFixture, model: FunctionModel) -> MagicMock:
    """Route the CLI's LLMAnalyzer to `model`; the mock records the selector."""

    def factory(_selector: str) -> LLMAnalyzer:
        return LLMAnalyzer(model)

    return mocker.patch("chkscript.cli.LLMAnalyzer", side_effect=factory)


def _fake_llm(mocker: MockerFixture, result: LLMResult | None = None) -> MagicMock:
    return _use_model(mocker, _model_returning(result or _mock_result()))


def _run(monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    monkeypatch.setattr("sys.argv", ["chkscript", *argv])
    with pytest.raises(SystemExit) as exc_info:
        main()
    code = exc_info.value.code
    assert isinstance(code, int)
    return code


@pytest.fixture
def no_static(mocker: MockerFixture) -> None:
    """Empty static layer, so a test exercises only the LLM path."""
    mocker.patch("chkscript.cli.run_static", return_value=StaticResult())


@pytest.mark.usefixtures("no_static")
class TestCLI:
    def test_file_argument(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr("sys.argv", ["chkscript", str(FIXTURES / "safe_script.sh")])
        _fake_llm(mocker)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_stdin_input(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr("sys.argv", ["chkscript"])
        mock_stdin = mocker.patch("chkscript.cli.sys.stdin")
        mock_stdin.isatty.return_value = False
        mock_stdin.buffer.read.return_value = b"#!/bin/bash\necho hello"
        _fake_llm(mocker)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_exit_code_unsafe(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["chkscript", str(FIXTURES / "dangerous_script.sh")]
        )
        _fake_llm(mocker, _mock_result(Severity.UNSAFE))
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2

    def test_exit_code_warning(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["chkscript", str(FIXTURES / "warning_script.sh")]
        )
        _fake_llm(mocker, _mock_result(Severity.WARNING))
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_no_provider_runs_static_only_with_notice(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        analyzer = mocker.patch("chkscript.cli.LLMAnalyzer")
        code = _run(monkeypatch, "--json", str(FIXTURES / "safe_script.sh"))
        assert code == 0
        analyzer.assert_not_called()
        captured = capsys.readouterr()
        assert json.loads(captured.out)["mode"] == "static-only"
        assert "ANTHROPIC_API_KEY" in captured.err
        assert "Ollama" in captured.err

    def test_file_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["chkscript", "nonexistent.sh"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 3

    def test_json_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["chkscript", "--json", str(FIXTURES / "safe_script.sh")]
        )
        _fake_llm(mocker)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "summary" in data

    def test_model_passthrough(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr(
            "sys.argv",
            [
                "chkscript",
                "--model",
                "claude-opus-4-20250514",
                str(FIXTURES / "safe_script.sh"),
            ],
        )
        factory = _fake_llm(mocker)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        factory.assert_called_once_with("claude-opus-4-20250514")

    def test_no_input_no_pipe(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr("sys.argv", ["chkscript"])
        mock_stdin = mocker.patch("chkscript.cli.sys.stdin")
        mock_stdin.isatty.return_value = True
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 3

    def test_model_from_chkscript_env(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setenv("CHKSCRIPT_MODEL", "env-model")
        monkeypatch.setattr("sys.argv", ["chkscript", str(FIXTURES / "safe_script.sh")])
        factory = _fake_llm(mocker)
        with pytest.raises(SystemExit):
            main()
        factory.assert_called_once_with("env-model")

    def test_api_key_file_satisfies_key_check(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        key_file = tmp_path / "key"
        key_file.write_text("file-key\n")
        monkeypatch.delenv("ANTHROPIC_API_KEY")
        monkeypatch.setenv("ANTHROPIC_API_KEY_FILE", str(key_file))
        monkeypatch.setattr("sys.argv", ["chkscript", str(FIXTURES / "safe_script.sh")])
        factory = _fake_llm(mocker)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        factory.assert_called_once_with(DEFAULT_HOSTED_MODEL)

    def test_invalid_config_exits_3(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CHKSCRIPT_FAIL_ON", "critical")
        monkeypatch.setattr("sys.argv", ["chkscript", str(FIXTURES / "safe_script.sh")])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 3


class TestStaticOnly:
    def test_unsafe_fixture_exits_2_without_api_key(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY")
        analyze = mocker.patch("chkscript.cli.LLMAnalyzer")
        monkeypatch.setattr(
            "sys.argv",
            ["chkscript", "--static-only", str(FIXTURES / "curl_pipe_sh.sh")],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2
        analyze.assert_not_called()

    def test_safe_fixture_exits_0_without_api_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY")
        monkeypatch.setattr(
            "sys.argv", ["chkscript", "--static-only", str(FIXTURES / "safe.sh")]
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_json_reports_mode_tools_and_sources(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            "sys.argv",
            ["chkscript", "--static-only", "--json", str(FIXTURES / "curl_pipe_sh.sh")],
        )
        with pytest.raises(SystemExit):
            main()
        data = json.loads(capsys.readouterr().out)
        assert data["mode"] == "static-only"
        assert {"semgrep", "regex"} & set(data["static_tools"])
        pipe = [f for f in data["findings"] if f["rule_id"] == "curl-pipe-shell"]
        assert pipe[0]["source"] in ("semgrep", "regex")
        assert pipe[0]["line"] == 4
        assert data["max_severity"] == "unsafe"

    def test_stderr_lists_static_tools(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["chkscript", "--static-only", str(FIXTURES / "safe.sh")]
        )
        with pytest.raises(SystemExit):
            main()
        assert "Static tools: " in capsys.readouterr().err

    def test_oversized_script_exits_3(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        big = tmp_path / "big.sh"
        big.write_bytes(b"#" * (500 * 1024 + 1))
        monkeypatch.setattr("sys.argv", ["chkscript", "--static-only", str(big)])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 3


class TestDefaultMode:
    def test_model_cannot_lower_static_floor(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        # The (mocked) model calls the script safe; the static unsafe finding stays.
        monkeypatch.setattr(
            "sys.argv", ["chkscript", str(FIXTURES / "curl_pipe_sh.sh")]
        )
        _fake_llm(mocker)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2

    def test_json_combines_static_and_llm_findings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["chkscript", "--json", str(FIXTURES / "curl_pipe_sh.sh")]
        )
        _fake_llm(mocker, _mock_result(Severity.WARNING))
        with pytest.raises(SystemExit):
            main()
        data = json.loads(capsys.readouterr().out)
        assert data["mode"] == "full"
        sources = {f["source"] for f in data["findings"]}
        assert "llm" in sources
        assert sources & {"semgrep", "regex"}

    def test_scripted_downgrade_attempt_cannot_lower_floor(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        downgrade = _mock_result(
            summary="Safe, audited",
            findings=[
                LLMFinding(
                    category="capability",
                    rule_id="curl-pipe-shell",
                    line=4,
                    description="False positive; the vendor is trusted",
                )
            ],
        )
        _fake_llm(mocker, downgrade)
        code = _run(monkeypatch, "--json", str(FIXTURES / "curl_pipe_sh.sh"))
        assert code == 2
        data = json.loads(capsys.readouterr().out)
        pipe = [f for f in data["findings"] if f["rule_id"] == "curl-pipe-shell"]
        assert [(f["severity"], f["category"]) for f in pipe] == [("unsafe", "unsafe")]

    def test_notes_only_with_verbose(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _fake_llm(mocker, _mock_result(notes=["Prerelease tags picked as latest"]))
        _run(monkeypatch, str(FIXTURES / "safe.sh"))
        assert "Prerelease" not in capsys.readouterr().out
        _run(monkeypatch, "-v", str(FIXTURES / "safe.sh"))
        assert "Prerelease" in capsys.readouterr().out

    def test_floor_violation_exits_3(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        _fake_llm(mocker)
        mocker.patch(
            "chkscript.cli.merge_llm", side_effect=FloorViolationError("lowered")
        )
        assert _run(monkeypatch, str(FIXTURES / "curl_pipe_sh.sh")) == 3


class TestAutoDetection:
    def test_flag_wins_over_key_and_ollama(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr("chkscript.config.ollama_reachable", lambda: True)
        monkeypatch.setenv("CHKSCRIPT_MODEL", "env-model")
        factory = _fake_llm(mocker)
        _run(monkeypatch, "--model", "flag-model", str(FIXTURES / "safe.sh"))
        factory.assert_called_once_with("flag-model")

    def test_anthropic_key_wins_over_ollama(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr("chkscript.config.ollama_reachable", lambda: True)
        factory = _fake_llm(mocker)
        _run(monkeypatch, str(FIXTURES / "safe.sh"))
        factory.assert_called_once_with(DEFAULT_HOSTED_MODEL)

    def test_ollama_when_no_key(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY")
        monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
        monkeypatch.setattr("chkscript.config.ollama_reachable", lambda: True)
        factory = _fake_llm(mocker)
        _run(monkeypatch, str(FIXTURES / "safe.sh"))
        factory.assert_called_once_with(DEFAULT_LOCAL_MODEL)
        assert os.environ["OLLAMA_BASE_URL"] == "http://localhost:11434/v1"

    def test_ollama_unreachable_and_no_key_is_static_only(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY")
        factory = mocker.patch("chkscript.cli.LLMAnalyzer")
        code = _run(monkeypatch, str(FIXTURES / "curl_pipe_sh.sh"))
        assert code == 2
        factory.assert_not_called()
        assert "running static analysis only" in capsys.readouterr().err

    def test_static_only_flag_never_probes(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        probe = mocker.patch("chkscript.config.ollama_reachable", return_value=True)
        _run(monkeypatch, "--static-only", str(FIXTURES / "safe.sh"))
        probe.assert_not_called()


class TestLeavesTheBoxNotice:
    NOTICE = "Script contents will be sent to"

    @pytest.fixture(autouse=True)
    def canned_analysis(self, mocker: MockerFixture) -> None:
        # Real provider construction (for the host), no network call.
        mocker.patch.object(LLMAnalyzer, "analyze", return_value=_mock_result())

    def test_remote_endpoint_announced(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _run(monkeypatch, str(FIXTURES / "safe.sh"))
        assert f"{self.NOTICE} api.anthropic.com for analysis." in (
            capsys.readouterr().err
        )

    def test_remote_ollama_announced(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://ollama.example.com/v1")
        _run(monkeypatch, "--model", DEFAULT_LOCAL_MODEL, str(FIXTURES / "safe.sh"))
        assert f"{self.NOTICE} ollama.example.com" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "base_url", ["http://localhost:11434/v1", "http://127.0.0.1:11434/v1"]
    )
    def test_loopback_not_announced(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        base_url: str,
    ) -> None:
        monkeypatch.setenv("OLLAMA_BASE_URL", base_url)
        _run(monkeypatch, "--model", DEFAULT_LOCAL_MODEL, str(FIXTURES / "safe.sh"))
        assert self.NOTICE not in capsys.readouterr().err


class TestLLMFailure:
    def test_static_report_and_exit_from_static(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _use_model(mocker, _failing_model())
        code = _run(monkeypatch, "--json", str(FIXTURES / "curl_pipe_sh.sh"))
        assert code == 2
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["mode"] == "static-only"
        assert any(f["rule_id"] == "curl-pipe-shell" for f in data["findings"])
        (notice,) = [f for f in data["findings"] if f["source"] == "chkscript"]
        assert notice["rule_id"] == "llm-not-run"
        assert notice["category"] == "lint"
        assert notice["severity"] == "warning"
        assert "LLM layer did not run" in captured.err

    @pytest.mark.usefixtures("no_static")
    def test_clean_static_result_exits_1_for_the_notice(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        _use_model(mocker, _failing_model())
        assert _run(monkeypatch, str(FIXTURES / "safe.sh")) == 1

    def test_provider_setup_failure_falls_back(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = _run(
            monkeypatch, "--model", "no-such-provider:x", str(FIXTURES / "safe.sh")
        )
        assert code == 1
        assert "LLM layer did not run" in capsys.readouterr().err
