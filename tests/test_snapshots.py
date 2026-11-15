"""Snapshots of the terminal report, `--static-only`, for real installers.

shellcheck is disabled so a snapshot depends on chkscript and shfmt, not on
the shellcheck version installed. Regenerate after an intended change with
`CHKSCRIPT_UPDATE_SNAPSHOTS=1 uv run pytest tests/test_snapshots.py`, then
review the diff like any other change.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from chkscript.cli import main
from chkscript.static import shellcheck
from tests.conftest import require_tool

ROOT = Path(__file__).parent
SNAPSHOTS = ROOT / "snapshots"

# installer -> (expected exit code, why it is in the snapshot set)
CASES: dict[str, int] = {
    # Capabilities only: root, a system write, a TLS-only download.
    "k3d-no-checksum": 1,
    # Unsafe findings above a full capability section.
    "ollama": 2,
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_terminal_report_snapshot(
    name: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    require_tool("shfmt")
    monkeypatch.setattr(shellcheck, "available", lambda: False)
    script = ROOT / "corpus" / name / "install.sh"
    monkeypatch.setattr("sys.argv", ["chkscript", "--static-only", str(script)])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == CASES[name]
    output = capsys.readouterr().out

    snapshot = SNAPSHOTS / f"{name}.txt"
    if os.environ.get("CHKSCRIPT_UPDATE_SNAPSHOTS"):
        snapshot.parent.mkdir(exist_ok=True)
        snapshot.write_text(output)
    assert output == snapshot.read_text()
