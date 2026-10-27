from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from chkscript import config
from chkscript.cli import main
from chkscript.config import (
    DEFAULT_MODEL,
    ConfigError,
    Settings,
    apply_secret_files,
    load_config,
)

FIXTURE_KEY = "sk-ant-fixture-0123456789-DO-NOT-LEAK"
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def clean_env() -> Iterator[None]:
    # patch.dict restores all of os.environ, including keys load_config exports.
    with patch.dict(os.environ):
        for name in list(os.environ):
            if name.startswith("CHKSCRIPT_") or "_API_KEY" in name:
                del os.environ[name]
        yield


def _key_file(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "api_key"
    path.write_text(content, encoding="utf-8")
    return path


class TestDefaults:
    def test_defaults_when_nothing_is_set(self) -> None:
        settings = load_config()
        assert settings.model == DEFAULT_MODEL
        assert settings.depth == 2
        assert settings.max_fetches == 5
        assert settings.fail_on == "warning"
        assert settings.no_follow is False

    def test_all_variables_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CHKSCRIPT_DEPTH", "4")
        monkeypatch.setenv("CHKSCRIPT_MAX_FETCHES", "0")
        monkeypatch.setenv("CHKSCRIPT_FAIL_ON", "unsafe")
        monkeypatch.setenv("CHKSCRIPT_NO_FOLLOW", "1")
        settings = load_config()
        assert settings.depth == 4
        assert settings.max_fetches == 0
        assert settings.fail_on == "unsafe"
        assert settings.no_follow is True

    def test_anthropic_key_implies_default_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", FIXTURE_KEY)
        assert Settings().model == DEFAULT_MODEL


class TestPrecedence:
    @pytest.fixture(autouse=True)
    def provider_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A provider default distinct from DEFAULT_MODEL, so each tier is visible.
        monkeypatch.setattr(
            config,
            "_PROVIDER_DEFAULT_MODELS",
            (("ANTHROPIC_API_KEY", "provider-model"),),
        )

    def test_default_when_no_provider_env(self) -> None:
        assert load_config().model == DEFAULT_MODEL

    def test_provider_env_beats_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", FIXTURE_KEY)
        assert load_config().model == "provider-model"

    def test_chkscript_env_beats_provider_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", FIXTURE_KEY)
        monkeypatch.setenv("CHKSCRIPT_MODEL", "env-model")
        assert load_config().model == "env-model"

    def test_flag_beats_chkscript_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", FIXTURE_KEY)
        monkeypatch.setenv("CHKSCRIPT_MODEL", "env-model")
        assert load_config(model="flag-model").model == "flag-model"


class TestValidation:
    def test_invalid_fail_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CHKSCRIPT_FAIL_ON", "critical")
        with pytest.raises(ConfigError, match="CHKSCRIPT_FAIL_ON"):
            load_config()

    @pytest.mark.parametrize("value", ["5", "-1", "two"])
    def test_invalid_depth(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("CHKSCRIPT_DEPTH", value)
        with pytest.raises(ConfigError, match="CHKSCRIPT_DEPTH"):
            load_config()

    def test_invalid_max_fetches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CHKSCRIPT_MAX_FETCHES", "-1")
        with pytest.raises(ConfigError, match="CHKSCRIPT_MAX_FETCHES"):
            load_config()

    def test_invalid_no_follow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CHKSCRIPT_NO_FOLLOW", "sometimes")
        with pytest.raises(ConfigError, match="CHKSCRIPT_NO_FOLLOW"):
            load_config()

    def test_empty_model_flag_rejected(self) -> None:
        with pytest.raises(ConfigError, match="CHKSCRIPT_MODEL"):
            load_config(model="")


class TestSecretFiles:
    def test_strips_one_trailing_newline(self, tmp_path: Path) -> None:
        path = _key_file(tmp_path, FIXTURE_KEY + "\n")
        env = {"ANTHROPIC_API_KEY_FILE": str(path)}
        apply_secret_files(env)
        assert env["ANTHROPIC_API_KEY"] == FIXTURE_KEY

    def test_strips_only_one_newline(self, tmp_path: Path) -> None:
        path = _key_file(tmp_path, FIXTURE_KEY + "\n\n")
        env = {"ANTHROPIC_API_KEY_FILE": str(path)}
        apply_secret_files(env)
        assert env["ANTHROPIC_API_KEY"] == FIXTURE_KEY + "\n"

    def test_no_trailing_newline_kept_as_is(self, tmp_path: Path) -> None:
        path = _key_file(tmp_path, FIXTURE_KEY)
        env = {"ANTHROPIC_API_KEY_FILE": str(path)}
        apply_secret_files(env)
        assert env["ANTHROPIC_API_KEY"] == FIXTURE_KEY

    def test_any_api_key_file_variable(self, tmp_path: Path) -> None:
        path = _key_file(tmp_path, "openai-key\n")
        env = {"OPENAI_API_KEY_FILE": str(path)}
        apply_secret_files(env)
        assert env["OPENAI_API_KEY"] == "openai-key"

    def test_direct_variable_wins(self, tmp_path: Path) -> None:
        path = _key_file(tmp_path, FIXTURE_KEY + "\n")
        env = {"ANTHROPIC_API_KEY": "direct", "ANTHROPIC_API_KEY_FILE": str(path)}
        apply_secret_files(env)
        assert env["ANTHROPIC_API_KEY"] == "direct"

    def test_missing_file(self, tmp_path: Path) -> None:
        env = {"ANTHROPIC_API_KEY_FILE": str(tmp_path / "missing")}
        with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY_FILE"):
            apply_secret_files(env)

    def test_empty_file(self, tmp_path: Path) -> None:
        env = {"ANTHROPIC_API_KEY_FILE": str(_key_file(tmp_path, "\n"))}
        with pytest.raises(ConfigError, match="empty"):
            apply_secret_files(env)

    def test_load_config_exports_to_process_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        path = _key_file(tmp_path, FIXTURE_KEY + "\n")
        monkeypatch.setenv("ANTHROPIC_API_KEY_FILE", str(path))
        load_config()
        assert os.environ["ANTHROPIC_API_KEY"] == FIXTURE_KEY


class TestNoKeyInErrors:
    def test_invalid_utf8_key_file(self, tmp_path: Path) -> None:
        path = tmp_path / "api_key"
        path.write_bytes(FIXTURE_KEY.encode() + b"\xff\n")
        with pytest.raises(ConfigError) as exc_info:
            apply_secret_files({"ANTHROPIC_API_KEY_FILE": str(path)})
        assert FIXTURE_KEY not in str(exc_info.value)

    def test_validation_error_omits_input(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A key pasted into the wrong variable must not be echoed back.
        monkeypatch.setenv("CHKSCRIPT_DEPTH", FIXTURE_KEY)
        monkeypatch.setenv("CHKSCRIPT_FAIL_ON", FIXTURE_KEY)
        with pytest.raises(ConfigError) as exc_info:
            load_config()
        assert FIXTURE_KEY not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__

    def test_cli_output_never_contains_key(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv(
            "ANTHROPIC_API_KEY_FILE", str(_key_file(tmp_path, FIXTURE_KEY + "\n"))
        )
        monkeypatch.setenv("CHKSCRIPT_FAIL_ON", FIXTURE_KEY)
        monkeypatch.setattr("sys.argv", ["chkscript", str(FIXTURES / "safe_script.sh")])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 3
        captured = capsys.readouterr()
        assert "CHKSCRIPT_FAIL_ON" in captured.err
        assert FIXTURE_KEY not in captured.out + captured.err
