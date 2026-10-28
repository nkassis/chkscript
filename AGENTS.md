# AGENTS.md

Developer tooling for chkscript, for every coding agent. Commands run from the repo root. Project rules (stack, guardrails, threat model, exit codes) are in `CLAUDE.md`.

## Setup

```sh
uv sync
pre-commit install --hook-type pre-commit --hook-type pre-push   # pre-commit itself: `uv tool install pre-commit`, once per machine
cp .env.example .env    # then fill in the placeholders
```

External tools, on `PATH`, never vendored or pip-installed by chkscript:

| Tool | Used for | Debian / Ubuntu | Arch |
| --- | --- | --- | --- |
| `shellcheck` | static layer, warning tier | `sudo apt install shellcheck` | `sudo pacman -S shellcheck` |
| `semgrep` | static layer, unsafe tier | `uv tool install semgrep` | `uv tool install semgrep` |
| `trufflehog` | pre-commit secret scan | release binary from github.com/trufflesecurity/trufflehog/releases (verify the checksum) into `~/.local/bin` | AUR: `trufflehog-git` (the `trufflehog` AUR package lags upstream) |

## Commands

| Command | What it does |
| --- | --- |
| `uv run ruff check .` | Lint (`--fix` to apply safe fixes) |
| `uv run black .` | Format (`--check` in CI) |
| `uv run pytest` | Tests |
| `pre-commit run --all-files` | Every hook against the whole tree |
| `uv run chkscript FILE` | Run the CLI |
| `uv run chkscript --static-only FILE` | Static layer only; no API key needed |
| `CHKSCRIPT_REQUIRE_TOOLS=1 uv run pytest` | As CI runs it: tests needing shellcheck/semgrep fail instead of skipping when the tool is missing |

Static layer layout: `src/chkscript/rules/*.yml` is the Semgrep ruleset (package data); `static/regex_rules.py` mirrors it with the same rule ids and messages, and `tests/test_rules.py` holds both engines to the same snippet corpus. Add a rule to both, plus cases to that corpus.

Real-installer corpus: `tests/corpus/<name>/` holds a pinned `install.sh`, its `SOURCE` (URL, fetch date, SHA-256, license) and upstream `LICENSE`. `tests/corpus/expected.toml` records each installer's agreed verdict, and `uv run pytest tests/test_corpus.py` fails on any drift under either engine. A rule change that moves a corpus result updates the matching entry (verdict and note) in the same PR. To refresh an installer, re-fetch it, update `SOURCE`, and re-agree its entry.
