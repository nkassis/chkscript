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

The default mode also requires an Anthropic API key (`--static-only` does not):

```bash
export ANTHROPIC_API_KEY='your-key-here'
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
