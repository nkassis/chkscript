# AGENT.md

Developer tooling. Commands run from the repo root.

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

## Claude Code hooks

`.claude/hooks/check-python.sh` runs from `.claude/settings.json`:
- **PostToolUse** (Edit/Write): Black formats the file, then Ruff lints it; findings block Claude until fixed.
- **Stop**: `ruff check .` across the project before Claude may finish.

Without `pyproject.toml` the hook falls back to `uvx` (ad-hoc tool versions). Needs `uv`; `jq` is used if present, else `python3`.

`stacks/shell` is deliberately not applied: `tests/fixtures/` and `tests/examples/` are intentionally bad Bash.
