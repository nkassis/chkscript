# chkscript

Bash script safety analyzer powered by Claude. Quickly audit shell scripts for unsafe actions, antipatterns, and understand what they install before running them.

## Install

```bash
uv tool install .
```

## Usage

```bash
# Analyze a file
chkscript install.sh

# Pipe from curl
curl -fsSL https://sh.rustup.rs | chkscript

# Pick the model
chkscript --model claude-haiku-5-5 install.sh

# JSON output
chkscript --json install.sh | jq '.findings[] | select(.severity == "unsafe")'

# Verbose mode (show all code snippets)
chkscript -v install.sh

# Static rules only: no model, no API key
chkscript --static-only install.sh
```

## Setup

`shellcheck` and `semgrep` on `PATH` are recommended. Without them chkscript falls back to its built-in regex rules and says so on stderr.

| Platform | shellcheck | semgrep |
|----------|------------|---------|
| Debian / Ubuntu | `sudo apt install shellcheck` | `uv tool install semgrep` |
| Arch | `sudo pacman -S shellcheck` | `uv tool install semgrep` |
| macOS | `brew install shellcheck` | `brew install semgrep` |

The default mode also requires an Anthropic API key (`--static-only` does not). Give it directly, or as a file:

```bash
export ANTHROPIC_API_KEY='your-key-here'
# or
export ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_api_key
```

Choose the model with `CHKSCRIPT_MODEL`:

```bash
export CHKSCRIPT_MODEL=claude-haiku-5-5
```

The model is `--model`, then `CHKSCRIPT_MODEL`, then the provider's default (`claude-sonnet-5-5` when an Anthropic key is set), then the local default `ollama:gpt-oss:20b`. The Ollama provider isn't wired up yet, so for now the default mode needs an Anthropic key. `.env.example` lists every variable.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Safe |
| 1 | Warnings only |
| 2 | Unsafe |
| 3 | Error |

## Development

```bash
uv sync --group dev
uv run pytest
```

Tests that need `shellcheck` or `semgrep` skip when the tool is missing. Set `CHKSCRIPT_REQUIRE_TOOLS=1` (CI does) to make a missing tool fail the run instead.
