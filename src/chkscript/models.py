from __future__ import annotations

from enum import IntEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(IntEnum):
    SAFE = 0
    WARNING = 1
    UNSAFE = 2


Source = Literal["shellcheck", "semgrep", "regex", "llm", "chkscript"]
StaticTool = Literal["shellcheck", "semgrep", "regex"]
Mode = Literal["full", "no-follow", "static-only"]
# lint: shellcheck output; capability: powerful but normal for an installer;
# unsafe: never legitimate in an installer (the floor). See docs/spec.md.
Category = Literal["lint", "capability", "unsafe"]
CATEGORY_RANK: dict[Category, int] = {"lint": 0, "capability": 1, "unsafe": 2}

ENTRY_FILE = "<entry>"


class ExtractedUrl(BaseModel):
    """A URL candidate found in a script; phase 4 uses these as the fetch allowlist."""

    model_config = ConfigDict(extra="forbid")

    url: str
    line: int = Field(ge=1)
    # "variable" when the URL is built from shell variables or substitutions.
    kind: Literal["literal", "variable"]


class ScriptBundle(BaseModel):
    """A preprocessed script: what every later stage reads instead of raw bytes."""

    model_config = ConfigDict(extra="forbid")

    file: str = ENTRY_FILE
    text: str
    # What the Semgrep and regex rules scan: `text` with backslash-newline
    # continuations joined, line numbers preserved (preprocess.join_continuations).
    rules_text: str
    numbered: str
    sha256: str
    size: int = Field(ge=0)
    urls: list[ExtractedUrl] = Field(default_factory=list)

    def line_text(self, line: int) -> str | None:
        lines = self.text.split("\n")
        if 1 <= line <= len(lines):
            return lines[line - 1]
        return None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    category: Category
    description: str
    # v0.1 free-text location from the model, e.g. "line 3"; superseded by `line`.
    line_reference: str | None = None
    snippet: str | None = None
    source: Source = "llm"
    rule_id: str | None = None
    file: str = ENTRY_FILE
    line: int | None = None
    merged_from: list[Source] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _default_category(cls, data: object) -> object:
        # Unset category follows severity, so findings built before categories
        # existed keep working: unsafe stays unsafe, anything else is a capability.
        if isinstance(data, dict) and data.get("category") is None:
            unsafe = data.get("severity") == Severity.UNSAFE
            data = {**data, "category": "unsafe" if unsafe else "capability"}
        return data


class LLMFinding(BaseModel):
    """A finding as the model reports it; the analyzer turns it into a `Finding`.

    Only what the model may say: source, file and severity are set by chkscript.
    """

    model_config = ConfigDict(extra="forbid")

    category: Literal["capability", "unsafe"] = Field(
        description="capability or unsafe, as defined in the instructions"
    )
    rule_id: str | None = Field(
        default=None,
        description=(
            "The rule_id of the static finding this raises, or a short kebab-case "
            "id of your own for a new finding"
        ),
    )
    line: int | None = Field(
        default=None, description="Line number copied from the numbered script"
    )
    description: str = Field(
        description="What the script does and, for a raise, the evidence for it"
    )
    snippet: str | None = Field(default=None, description="The relevant code")


class LLMResult(BaseModel):
    """The model's structured output."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(description="What the script does, in two or three lines")
    findings: list[LLMFinding] = Field(default_factory=list)
    notes: list[str] = Field(
        default_factory=list,
        description="Code-quality observations that are not safety findings",
    )


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
    mode: Mode = "full"
    static_tools: list[StaticTool] = Field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.SAFE
        return max(f.severity for f in self.findings)
