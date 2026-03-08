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
```

## Setup

Requires an Anthropic API key:

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
