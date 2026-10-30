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
curl -fsSL https://example.com/install.sh | chkscript

# JSON output
chkscript --json script.sh | jq '.findings[] | select(.severity == "unsafe")'

# Verbose mode (show all code snippets)
chkscript -v script.sh

# Static rules only: no model, no API key
chkscript --static-only script.sh
```

## Setup

`shellcheck` and `semgrep` on `PATH` are recommended (`sudo apt install shellcheck`, `uv tool install semgrep`). Without them chkscript falls back to its built-in regex rules and says so on stderr.

The default mode adds a model on top of the static rules. It picks one in this order: `--model` or `CHKSCRIPT_MODEL` (a pydantic-ai `provider:model` selector), then `anthropic:claude-sonnet-5-5` when `ANTHROPIC_API_KEY` is set, then `ollama:gpt-oss:20b` when Ollama answers at `OLLAMA_BASE_URL` (default `http://localhost:11434/v1`). If none of these applies, it runs the static rules only and says so on stderr. When the script will go to a non-local endpoint, stderr says which host.

```bash
export ANTHROPIC_API_KEY='your-key-here'   # or: ollama pull gpt-oss:20b
```

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

`uv run pytest --run-live` also runs the model fixtures in `tests/test_live.py` against a real provider: Ollama by default, or whatever `CHKSCRIPT_MODEL` names. Not run in CI.
