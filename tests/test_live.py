"""Model fixtures against a real provider. Opt-in: `uv run pytest --run-live`.

The model is CHKSCRIPT_MODEL when set, else the local default (Ollama). Never
in CI: it needs a running provider and the verdicts are not deterministic
across models.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from chkscript.analyzer import LLMAnalyzer, merge_llm
from chkscript.config import DEFAULT_LOCAL_MODEL, load_config, resolve_model
from chkscript.models import Finding, Severity
from chkscript.preprocess import preprocess
from chkscript.static import run_static

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass(frozen=True)
class Expected:
    # None: the static rules decide it and they are still moving (NIM-122/123).
    max_severity: Severity | None
    # True: the model must report something unsafe (a raise or a new finding).
    # False: it must report nothing unsafe. None: no expectation of the model.
    llm_unsafe: bool | None = None


# fixture -> expected outcome of a full (static + model) run
LIVE_EXPECTED: dict[str, Expected] = {
    "curl_pipe_sh.sh": Expected(Severity.UNSAFE),
    "injection_comment.sh": Expected(Severity.UNSAFE),
    # The static curl | sh finding must survive the fake "</script>" and the
    # instructions after it.
    "injection_delimiter.sh": Expected(Severity.UNSAFE),
    # c=curl; $c ... | $s: the model must see through the variables (the static
    # engine catches it too once constants are substituted, NIM-122).
    "evasion_var_cmd.sh": Expected(Severity.UNSAFE, llm_unsafe=True),
    # GitHub's documented apt key setup and a TLS-only GitHub release download
    # are capabilities; the model must not raise either to unsafe. Max severity
    # becomes warning once NIM-122/123 land (today the static rules call the
    # wget | tee line curl-pipe-shell and the download unsafe).
    "tls_release_apt_key.sh": Expected(None, llm_unsafe=False),
    # Claims the official kubectl release, downloads from an unrelated host.
    "mismatched_host.sh": Expected(Severity.UNSAFE, llm_unsafe=True),
}


def _live_model() -> str:
    # Ollama unless CHKSCRIPT_MODEL says otherwise, even with ANTHROPIC_API_KEY set.
    selector = os.environ.get("CHKSCRIPT_MODEL") or DEFAULT_LOCAL_MODEL
    model = resolve_model(load_config(model=selector))
    assert model is not None
    return model


def _llm_unsafe(findings: list[Finding]) -> bool:
    return any(
        f.severity == Severity.UNSAFE and "llm" in (f.merged_from or [f.source])
        for f in findings
    )


@pytest.mark.live
@pytest.mark.parametrize("name", sorted(LIVE_EXPECTED))
def test_model_fixture(name: str) -> None:
    expected = LIVE_EXPECTED[name]
    bundle = preprocess((FIXTURES / name).read_bytes())
    static = run_static(bundle).findings
    llm = LLMAnalyzer(_live_model()).analyze(bundle, static)
    merged = merge_llm(static, llm, bundle)

    if expected.llm_unsafe is not None:
        assert _llm_unsafe(merged) == expected.llm_unsafe, merged
    if expected.max_severity is not None:
        assert max(f.severity for f in merged) == expected.max_severity, merged
