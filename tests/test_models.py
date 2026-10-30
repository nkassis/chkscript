from __future__ import annotations

import pytest

from chkscript.models import Finding, Severity


@pytest.mark.parametrize(
    ("severity", "category"),
    [(Severity.UNSAFE, "unsafe"), (Severity.WARNING, "capability")],
)
def test_category_defaults_from_severity(severity: Severity, category: str) -> None:
    assert Finding(severity=severity, description="x").category == category


def test_explicit_category_kept() -> None:
    finding = Finding(severity=Severity.WARNING, category="lint", description="x")
    assert finding.category == "lint"


def test_category_survives_copy_and_json_round_trip() -> None:
    finding = Finding(severity=Severity.WARNING, category="lint", description="x")
    assert Finding.model_validate_json(finding.model_dump_json()).category == "lint"
    raised = finding.model_copy(update={"severity": Severity.UNSAFE})
    assert raised.category == "lint"  # model_copy never re-derives; callers set both
