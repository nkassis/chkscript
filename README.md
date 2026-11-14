# chkscript

Bash script safety analyzer. Audits shell scripts, usually installers about to be piped into `sh`, for unsafe actions and tells you what they install before you run them. Deterministic rules set the floor; a model, hosted or local, adds intent analysis on top and can only raise findings, never lower them.

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

# Pick the model (pydantic-ai provider:model selector)
chkscript --model anthropic:claude-haiku-5-5 install.sh
chkscript --model ollama:gpt-oss:20b install.sh

# JSON output
chkscript --json install.sh | jq '.findings[] | select(.severity == "unsafe")'

# Verbose mode (show all code snippets)
chkscript -v install.sh

# Static rules only: no model, no API key
chkscript --static-only install.sh
```

## Setup

`shellcheck` and `shfmt` (v3.14.0 or newer) on `PATH` are recommended. Without shfmt, or with an older one, chkscript falls back to its built-in regex rules, which over-report, and says so on stderr.

| Platform | shellcheck | shfmt |
|----------|------------|-------|
| Debian / Ubuntu | `sudo apt install shellcheck` | `sudo apt install shfmt` if it is v3.14.0 or newer, else the release binary below |
| Arch | `sudo pacman -S shellcheck` | `sudo pacman -S shfmt` |
| macOS | `brew install shellcheck` | `brew install shfmt` |

shfmt release binary (Linux x86-64; other platforms are on the same release page), checksum verified before it is installed:

```sh
curl -fsSLo shfmt https://github.com/mvdan/sh/releases/download/v3.14.1/shfmt_v3.14.1_linux_amd64
echo "76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf  shfmt" | sha256sum -c -
install -m 0755 shfmt ~/.local/bin/shfmt
```

## Models

The default mode runs a model on top of the static rules. It picks one in this order:

1. `--model` or `CHKSCRIPT_MODEL`
2. `anthropic:claude-sonnet-5-5` when `ANTHROPIC_API_KEY` is set
3. `ollama:gpt-oss:20b` when Ollama answers at `OLLAMA_BASE_URL`
4. none: static rules only, with a notice on stderr

| Provider | Selector | Needs |
|----------|----------|-------|
| Anthropic | `anthropic:claude-sonnet-5-5` | `ANTHROPIC_API_KEY` |
| Ollama (local) | `ollama:gpt-oss:20b` | `ollama pull gpt-oss:20b`; `OLLAMA_BASE_URL` if not `http://localhost:11434/v1` |
| OpenAI, or OpenAI-compatible (vLLM, llama.cpp server, OpenRouter) | `openai:<model>` | `OPENAI_API_KEY` for OpenAI; `OPENAI_BASE_URL` for others, plus a key if the endpoint wants one |

```bash
# Local: nothing leaves the machine
ollama pull gpt-oss:20b
chkscript install.sh

# Hosted
export ANTHROPIC_API_KEY='your-key-here'
```

Any `*_API_KEY` can be given as a file instead (Docker secrets, systemd credentials). Keys are never accepted on the command line.

```bash
export ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_api_key
```

When the script will be sent to a non-local endpoint, stderr names the host first. `.env.example` lists every variable.

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

Tests that need `shellcheck` or `shfmt` skip when the tool is missing. Set `CHKSCRIPT_REQUIRE_TOOLS=1` (CI does) to make a missing tool fail the run instead.

`uv run pytest --run-live` also runs the model fixtures in `tests/test_live.py` against a real provider: Ollama by default, or whatever `CHKSCRIPT_MODEL` names. Not run in CI.
