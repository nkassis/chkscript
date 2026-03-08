# chkscript

Bash script safety analyzer using Claude API.

## Project structure

- `src/chkscript/` - source code (src layout with hatchling)
- `tests/` - pytest tests with fixtures in `tests/fixtures/`
- Single runtime dependency: `anthropic`

## Key commands

- `uv run chkscript` - run the CLI
- `uv run pytest` - run tests
- `uv sync --group dev` - install dev dependencies

## Architecture

- `models.py` - Severity enum, Finding/AnalysisResult dataclasses
- `analyzer.py` - Claude API call, prompt, JSON response parsing
- `formatter.py` - terminal (ANSI colors) and JSON output
- `cli.py` - argparse, entry point, orchestration

## Conventions

- Python 3.13+, `from __future__ import annotations`
- No unnecessary dependencies (raw ANSI codes, stdlib argparse)
- Exit codes: 0=safe, 1=warning, 2=unsafe, 3=error
