"""Settings resolution: flag, then CHKSCRIPT_*, then provider env, then default.

Secrets are never stored on Settings. Provider keys stay in the environment,
where the SDKs read them; `apply_secret_files` only turns `*_API_KEY_FILE` into
`*_API_KEY` before any SDK initializes.
"""

from __future__ import annotations

import os
from collections.abc import MutableMapping
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default models. Hosted is the Anthropic model the v0.1 analyzer calls; local is
# the Ollama selector used when no provider variable is set (wired in phase 3).
DEFAULT_HOSTED_MODEL = "claude-sonnet-5-5"
DEFAULT_LOCAL_MODEL = "ollama:gpt-oss-20b"

ENV_PREFIX = "CHKSCRIPT_"

_SECRET_FILE_SUFFIX = "_API_KEY_FILE"

# Provider variable whose presence implies a provider, and that provider's model.
# Checked in order; the first variable that is set wins.
_PROVIDER_DEFAULT_MODELS: tuple[tuple[str, str], ...] = (
    ("ANTHROPIC_API_KEY", DEFAULT_HOSTED_MODEL),
)

FailOn = Literal["warning", "unsafe"]


class ConfigError(Exception):
    """Invalid configuration. Messages name variables and paths, never values."""


def _provider_default_model() -> str:
    for variable, model in _PROVIDER_DEFAULT_MODELS:
        if os.environ.get(variable):
            return model
    return DEFAULT_LOCAL_MODEL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix=ENV_PREFIX, extra="ignore")

    model: str = Field(default_factory=_provider_default_model, min_length=1)
    depth: int = Field(default=2, ge=0, le=4)
    max_fetches: int = Field(default=5, ge=0)
    fail_on: FailOn = "warning"
    no_follow: bool = False


def _read_secret_file(variable: str, path: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"{variable} ({path}) is not valid UTF-8") from None
    except OSError as e:
        reason = e.strerror or type(e).__name__
        raise ConfigError(f"Cannot read {variable} ({path}): {reason}") from None
    if value.endswith("\n"):
        value = value[:-1]
    if not value:
        raise ConfigError(f"{variable} ({path}) is empty")
    return value


def apply_secret_files(environ: MutableMapping[str, str] | None = None) -> None:
    """Set each `X_API_KEY` from `X_API_KEY_FILE`, unless `X_API_KEY` is set."""
    env = os.environ if environ is None else environ
    for variable in sorted(k for k in env if k.endswith(_SECRET_FILE_SUFFIX)):
        target = variable.removesuffix("_FILE")
        if env.get(target):
            continue
        env[target] = _read_secret_file(variable, env[variable])


def _describe(error: ValidationError) -> str:
    # Built from field names and pydantic's messages only, never the input value.
    problems = []
    for detail in error.errors(include_input=False, include_url=False):
        field = str(detail["loc"][0]) if detail["loc"] else "settings"
        problems.append(f"{ENV_PREFIX}{field.upper()}: {detail['msg']}")
    return "Invalid configuration: " + "; ".join(problems)


def load_config(model: str | None = None) -> Settings:
    """Resolve settings. Arguments are command-line flags; None means not given."""
    apply_secret_files()
    overrides: dict[str, str] = {}
    if model is not None:
        overrides["model"] = model
    try:
        return Settings(**overrides)
    except ValidationError as e:
        raise ConfigError(_describe(e)) from None
