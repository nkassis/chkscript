from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    SAFE = 0
    WARNING = 1
    UNSAFE = 2


@dataclass
class Finding:
    severity: Severity
    description: str
    line_reference: str | None = None
    snippet: str | None = None


@dataclass
class AnalysisResult:
    summary: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.SAFE
        return max(f.severity for f in self.findings)
