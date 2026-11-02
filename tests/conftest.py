from __future__ import annotations

import os
import shutil

import pytest

# CI sets this so a missing external tool fails the run instead of skipping.
REQUIRE_TOOLS_ENV = "CHKSCRIPT_REQUIRE_TOOLS"


def require_tool(name: str) -> None:
    """Skip the calling test when `name` is not on PATH, or fail under CI."""
    if shutil.which(name) is not None:
        return
    if os.environ.get(REQUIRE_TOOLS_ENV):
        pytest.fail(f"{name} is required ({REQUIRE_TOOLS_ENV} is set) but not on PATH")
    pytest.skip(f"{name} not on PATH")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run the model fixtures against a real provider (Ollama by default).",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "live: calls a real model provider; runs only with --run-live"
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--run-live"):
        return
    skip = pytest.mark.skip(reason="needs --run-live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)
