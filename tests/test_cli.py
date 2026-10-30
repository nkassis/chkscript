from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from pytest_mock import MockerFixture

from chkscript.cli import main
from chkscript.models import AnalysisResult, Finding, Severity
from chkscript.static import StaticResult

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def set_api_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # patch.dict restores all of os.environ, including keys load_config exports.
    with patch.dict(os.environ):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        yield


def _mock_result(
    severity: Severity = Severity.SAFE, **kwargs: object
) -> AnalysisResult:
    defaults = dict(summary="Test result", findings=[], notes=[])
    defaults.update(kwargs)
    if severity == Severity.UNSAFE:
        defaults["findings"] = [
            Finding(severity=Severity.UNSAFE, description="Bad thing")
        ]
    elif severity == Severity.WARNING:
        defaults["findings"] = [
            Finding(severity=Severity.WARNING, description="Minor thing")
        ]
    return AnalysisResult(**defaults)


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
        mocker.patch("chkscript.cli.analyze", return_value=_mock_result())
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
        mocker.patch("chkscript.cli.analyze", return_value=_mock_result())
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_exit_code_unsafe(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["chkscript", str(FIXTURES / "dangerous_script.sh")]
        )
        mocker.patch(
            "chkscript.cli.analyze", return_value=_mock_result(Severity.UNSAFE)
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2

    def test_exit_code_warning(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["chkscript", str(FIXTURES / "warning_script.sh")]
        )
        mocker.patch(
            "chkscript.cli.analyze", return_value=_mock_result(Severity.WARNING)
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_missing_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setattr("sys.argv", ["chkscript", str(FIXTURES / "safe_script.sh")])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 3

    def test_file_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["chkscript", "nonexistent.sh"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 3

    def test_unknown_flag_exits_3(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("sys.argv", ["chkscript", "--bogus"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 3
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "usage: chkscript" in captured.err
        assert "--bogus" in captured.err

    def test_help_exits_0(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("sys.argv", ["chkscript", "--help"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        assert "usage: chkscript" in capsys.readouterr().out

    def test_json_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["chkscript", "--json", str(FIXTURES / "safe_script.sh")]
        )
        mocker.patch("chkscript.cli.analyze", return_value=_mock_result())
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
        mock_analyze = mocker.patch(
            "chkscript.cli.analyze", return_value=_mock_result()
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_analyze.assert_called_once()
        _, kwargs = mock_analyze.call_args
        assert kwargs["model"] == "claude-opus-4-20250514"

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
        mock_analyze = mocker.patch(
            "chkscript.cli.analyze", return_value=_mock_result()
        )
        with pytest.raises(SystemExit):
            main()
        _, kwargs = mock_analyze.call_args
        assert kwargs["model"] == "env-model"

    def test_api_key_file_satisfies_key_check(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        key_file = tmp_path / "key"
        key_file.write_text("file-key\n")
        monkeypatch.delenv("ANTHROPIC_API_KEY")
        monkeypatch.setenv("ANTHROPIC_API_KEY_FILE", str(key_file))
        monkeypatch.setattr("sys.argv", ["chkscript", str(FIXTURES / "safe_script.sh")])
        mocker.patch("chkscript.cli.analyze", return_value=_mock_result())
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

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
        analyze = mocker.patch("chkscript.cli.analyze")
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
        mocker.patch("chkscript.cli.analyze", return_value=_mock_result())
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
        mocker.patch(
            "chkscript.cli.analyze", return_value=_mock_result(Severity.WARNING)
        )
        with pytest.raises(SystemExit):
            main()
        data = json.loads(capsys.readouterr().out)
        assert data["mode"] == "full"
        sources = {f["source"] for f in data["findings"]}
        assert "llm" in sources
        assert sources & {"semgrep", "regex"}
