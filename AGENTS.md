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
| `shfmt` v3.14.0+ | static layer, syntax tree for the unsafe tier | `sudo apt install shfmt` if the package is v3.14.0 or newer, else the release binary from github.com/mvdan/sh/releases (verify the checksum) into `~/.local/bin` | `sudo pacman -S shfmt` |
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
| `CHKSCRIPT_REQUIRE_TOOLS=1 uv run pytest` | As CI runs it: tests needing shellcheck/shfmt fail instead of skipping when the tool is missing |
| `uv run pytest --run-live` | Also run the model fixtures (`tests/test_live.py`) against a real provider: Ollama, or `CHKSCRIPT_MODEL`. Never in CI |

Static layer layout: `static/shfmt.py` runs `shfmt --to-json`; `static/commands.py` turns the tree into the command model (executed commands, wrappers stripped, constants resolved, embedded code, generated files, downloads); `static/rules/` holds the rules as Python functions over that model, with ids and messages in `rules/catalog.py`; `static/regex_rules.py` is the fallback for when shfmt is missing or cannot parse a file, with the same ids and messages. `tests/test_commands.py` covers the model on snippets parsed by the real shfmt; `tests/test_rules.py` runs every rule snippet through both engines; `tests/test_fallback_superset.py` checks that the fallback reports every unsafe finding the engine does on the corpus and fixtures. Add a rule to `rules/` and `regex_rules.py`, plus a hit and a miss to `tests/test_rules.py`.

Real-installer corpus: `tests/corpus/<name>/` holds a pinned `install.sh`, its `SOURCE` (URL, fetch date, SHA-256, license) and upstream `LICENSE`. `tests/corpus/expected.toml` records each installer's agreed verdict, and `uv run pytest tests/test_corpus.py` fails on any drift under either engine. A rule change that moves a corpus result updates the matching entry (verdict and note) in the same PR. To refresh an installer, re-fetch it, update `SOURCE`, and re-agree its entry.
