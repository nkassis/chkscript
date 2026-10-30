"""Settings resolution: flag, then CHKSCRIPT_*, then provider env, then auto-detect.

Secrets are never stored on Settings. Provider keys stay in the environment,
where the SDKs read them; `apply_secret_files` only turns `*_API_KEY_FILE` into
`*_API_KEY` before any SDK initializes.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from collections.abc import Callable, MutableMapping
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default models, in pydantic-ai's provider:model form. Hosted is used when
# ANTHROPIC_API_KEY is set; local when Ollama answers on its base URL.
DEFAULT_HOSTED_MODEL = "anthropic:claude-sonnet-5-5"
DEFAULT_LOCAL_MODEL = "ollama:gpt-oss:20b"

OLLAMA_BASE_URL_ENV = "OLLAMA_BASE_URL"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"
_OLLAMA_PROBE_TIMEOUT_SECONDS = 0.5

ENV_PREFIX = "CHKSCRIPT_"

_SECRET_FILE_SUFFIX = "_API_KEY_FILE"

# Provider variable whose presence implies a provider, and that provider's model.
# Checked in order; the first variable that is set wins.
_PROVIDER_DEFAULT_MODELS: tuple[tuple[str, str], ...] = (
    ("ANTHROPIC_API_KEY", DEFAULT_HOSTED_MODEL),
)

NO_MODEL_NOTICE = (
    "No model available; running static analysis only. Set ANTHROPIC_API_KEY, "
    f"or start Ollama ({DEFAULT_OLLAMA_BASE_URL}), to enable the LLM layer."
)

FailOn = Literal["warning", "unsafe"]


class ConfigError(Exception):
    """Invalid configuration. Messages name variables and paths, never values."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix=ENV_PREFIX, extra="ignore")

    # Flag or CHKSCRIPT_MODEL only; None means auto-detect (`resolve_model`).
    model: str | None = Field(default=None, min_length=1)
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


def ollama_base_url() -> str:
    return os.environ.get(OLLAMA_BASE_URL_ENV) or DEFAULT_OLLAMA_BASE_URL


def ollama_reachable() -> bool:
    """True when Ollama answers its model listing within a short timeout."""
    root = ollama_base_url().rstrip("/").removesuffix("/v1")
    try:
        with urllib.request.urlopen(
            f"{root}/api/tags", timeout=_OLLAMA_PROBE_TIMEOUT_SECONDS
        ) as response:
            return bool(response.status == 200)
    except (OSError, ValueError):  # URLError and timeouts are OSErrors
        return False


def resolve_model(
    settings: Settings, probe: Callable[[], bool] | None = None
) -> str | None:
    """Pick the model: flag or env, provider key, local Ollama, else None.

    None means no model is available and the run is static-only. When the result
    is an Ollama model, OLLAMA_BASE_URL is set to its default if unset, because
    pydantic-ai's Ollama provider requires it.
    """
    model = settings.model
    if model is None:
        model = next(
            (m for variable, m in _PROVIDER_DEFAULT_MODELS if os.environ.get(variable)),
            None,
        )
    if model is None and (probe or ollama_reachable)():
        model = DEFAULT_LOCAL_MODEL
    if model is not None and model.startswith("ollama:"):
        os.environ[OLLAMA_BASE_URL_ENV] = ollama_base_url()
    return model
