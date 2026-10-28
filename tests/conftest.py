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
