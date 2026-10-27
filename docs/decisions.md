# Decisions

One line per deviation from a global default or other design choice, newest last: `YYYY-MM-DD — what was chosen — why`.

- 2026-10-26 — Python 3.11 floor instead of the template's 3.13 — wider install base for a CLI; nothing needs newer.
- 2026-10-26 — stdlib `logging` instead of structlog — a CLI whose logs are never shipped or queried (the global default's own exit).
- 2026-10-26 — `argparse` instead of Click — single command, no extra dependency.
- 2026-10-26 — no mypy; type hints enforced by Ruff `ANN` — matches the stack's Black plus Ruff hook contract.
- 2026-10-26 — `stacks/shell` not applied — `tests/fixtures/` and `tests/examples/` are intentionally bad Bash and its hook would block edits there.
- 2026-10-26 — tests stay in `tests/` — existing layout, which the template allows.
- 2026-10-26 — when both `X_API_KEY` and `X_API_KEY_FILE` are set, `X_API_KEY` wins — matches "env already set wins"; the spec does not say.
- 2026-10-26 — `CHKSCRIPT_DEPTH` above 4 is rejected (exit 3), not clamped — the spec says "capped at 4"; an explicit error beats a silent change.
- 2026-10-26 — default models: `claude-sonnet-5-5` when `ANTHROPIC_API_KEY` is set, else `ollama:gpt-oss-20b` — v0.1's `claude-sonnet-4-20250514` is retired (404); chosen by the maintainer during NIM-71. The Ollama default is resolved now but only usable once phase 3 wires the provider.
