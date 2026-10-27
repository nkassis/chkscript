from __future__ import annotations

from enum import IntEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(IntEnum):
    SAFE = 0
    WARNING = 1
    UNSAFE = 2


Source = Literal["shellcheck", "semgrep", "regex", "llm", "chkscript"]

ENTRY_FILE = "<entry>"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    description: str
    # v0.1 free-text location from the model, e.g. "line 3"; superseded by `line`.
    line_reference: str | None = None
    snippet: str | None = None
    source: Source = "llm"
    rule_id: str | None = None
    file: str = ENTRY_FILE
    line: int | None = None
    merged_from: list[Source] = Field(default_factory=list)


class FetchRecord(BaseModel):
    """One node of the fetch tree: a file that was analyzed, and why."""

    model_config = ConfigDict(extra="forbid")

    url: str
    depth: int = Field(ge=0)
    parent: str | None = None
    sha256: str
    size: int = Field(ge=0)
    reason: str | None = None


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    findings: list[Finding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.SAFE
        return max(f.severity for f in self.findings)
