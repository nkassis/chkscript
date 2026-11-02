# chkscript

chkscript is a CLI that tells people whether a shell script (usually an installer about to be piped into `sh`) is safe to run, and why. It layers deterministic scanners (shellcheck, Semgrep, a regex fallback) under an LLM that adds intent analysis. The one thing it must get right: no text inside a scanned script can lower the severity of a deterministic finding. The v0.2 design is `docs/spec.md` (branch `docs/v0.2-spec` until merged).

`AGENTS.md` has the tooling (setup, external tools, commands, corpus workflow) and is imported below. When a question is not answered here, stop and ask; do not decide silently.

@AGENTS.md

## Stack

- Python 3.11 floor, managed with `uv`. Never `pip install`; add dependencies with `uv add` (and only after asking).
- CLI on stdlib `argparse`; stdlib `logging` for diagnostics to stderr (never `print()`); `pydantic` at every external boundary, `pydantic-settings` for config. See `docs/decisions.md`.
- `pytest` + `pytest-mock`. Tests live in `tests/`, fixtures in `tests/fixtures/`.
- Type hints on every function signature, enforced by Ruff `ANN`.

## Guardrails (enforced, not optional)

| Rule | Claude hook | pre-commit | CI |
| --- | --- | --- | --- |
| Black formatting (don't hand-format; let Black decide) | applied on every edit | yes | `black --check` |
| Ruff lint clean | blocks on every edit; `ruff check .` before stopping | yes | yes |
| Tests pass | — | on push | yes |
| No secrets committed | — | trufflehog, detect-private-key | secret-scan |

If a hook blocks you, fix the reported problem. Do not add `# noqa` or per-file ignores to get past it without saying why.

## Done means

`uv run ruff check . && uv run black --check . && uv run pytest` passes.

## Rules

- **Layout** (`src/chkscript/`): `cli.py` argparse and orchestration; `config.py` flag/env resolution, `_FILE` secrets, the default model; `models.py` Pydantic models; `analyzer.py` the LLM call; `formatter.py` terminal and JSON. Planned by later phases, not yet present: `preprocess.py`, `static/` (shellcheck, semgrep, regex_rules, merge), `fetch.py`, and `rules/` for Semgrep YAML. Do not add empty stubs.
- **Run modes:** full (default: static + LLM + nested fetch), `--no-follow` (static + LLM, no fetch tool), `--static-only` (no model). Today the default mode is static + `LLMAnalyzer` with no fetch tool; the fetch tool and `--no-follow` are phase 4.
- **Threat model, non-negotiable:** (1) no text inside a scanned script can lower the severity of a deterministic finding; (2) the scanner never executes anything it analyzes, and never fetches anything not literally referenced by a script already in hand.
- **The model never lowers the floor.** The LLM layer may add findings or raise severity; it never removes or downgrades a static finding.
- **Secrets:** provider keys only from the SDK's own env names or `*_API_KEY_FILE`; never on the command line; never in output, errors, verbose mode or JSON.
- **Exit codes:**

| Code | Meaning |
| --- | --- |
| 0 | No finding at or above `--fail-on` |
| 1 | Highest finding is `warning` |
| 2 | At least one `unsafe` finding |
| 3 | Error: bad input, oversized script, config error, provider failure with no static result |

## Claude Code hooks

`.claude/hooks/check-python.sh` runs from `.claude/settings.json`:
- **PostToolUse** (Edit/Write): Black formats the file, then Ruff lints it; findings block Claude until fixed.
- **Stop**: `ruff check .` across the project before Claude may finish.

Without `pyproject.toml` the hook falls back to `uvx` (ad-hoc tool versions). Needs `uv`; `jq` is used if present, else `python3`.

`.claude/hooks/guard-bash.sh` (from claude-code-patterns `security/`) runs as **PreToolUse** on Bash: it blocks committing on, pushing to, or deleting `main`/`master`, and any force push. It reads the command line, so it catches mistakes, not bypasses; the server-side branch ruleset is the gate.

`stacks/shell` is deliberately not applied: `tests/fixtures/` is intentionally bad Bash and `tests/corpus/` holds verbatim third-party installers.
