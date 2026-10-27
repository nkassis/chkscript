from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from chkscript.cli import main
from chkscript.models import AnalysisResult, Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def set_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")


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
        mock_stdin.read.return_value = "#!/bin/bash\necho hello"
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
