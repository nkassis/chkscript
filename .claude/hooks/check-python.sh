#!/usr/bin/env bash
# Claude Code hook: enforce Black + Ruff on Python files.
#   check-python.sh edit  -> PostToolUse: format the edited file, then lint it
#   check-python.sh stop  -> Stop: lint the whole project before Claude finishes
# Exit 2 blocks and feeds stderr back to Claude; exit 1 is a non-blocking warning.
set -euo pipefail

mode="${1:-edit}"
input="$(cat)"
cd "${CLAUDE_PROJECT_DIR:-$PWD}"

json_field() {
    # Prefer jq; fall back to python3 so the hook works without extra installs.
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$input" | jq -r "$1 // empty"
    else
        printf '%s' "$input" | python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1].lstrip(".").split("."):
    value = value.get(key) if isinstance(value, dict) else None
print("" if value is None else str(value).lower() if isinstance(value, bool) else value)
' "$1"
    fi
}

# Use the project's pinned tools when there is a project; otherwise run them ad hoc.
run() {
    if [[ -f pyproject.toml ]]; then
        uv run --quiet "$@"
    else
        uvx --quiet "$@"
    fi
}

require_uv() {
    command -v uv >/dev/null 2>&1 && return 0
    echo "check-python: uv not found; Python lint skipped. Install uv: https://docs.astral.sh/uv/" >&2
    exit 1
}

case "$mode" in
    edit)
        file="$(json_field .tool_input.file_path)"
        [[ "$file" == *.py || "$file" == *.pyi ]] || exit 0
        [[ -f "$file" ]] || exit 0
        require_uv
        run black --quiet "$file" >&2 || true
        if ! out="$(run ruff check --fix --quiet "$file" 2>&1)"; then
            printf 'ruff found problems in %s; fix them:\n%s\n' "$file" "$out" >&2
            exit 2
        fi
        ;;
    stop)
        # Don't loop: if Claude is already continuing because of this hook, let it stop.
        [[ "$(json_field .stop_hook_active)" == "true" ]] && exit 0
        [[ -f pyproject.toml ]] || exit 0
        require_uv
        if ! out="$(run ruff check --quiet . 2>&1)"; then
            printf 'ruff check . fails; fix before finishing:\n%s\n' "$out" >&2
            exit 2
        fi
        ;;
    *)
        echo "check-python: unknown mode '$mode'" >&2
        exit 1
        ;;
esac
