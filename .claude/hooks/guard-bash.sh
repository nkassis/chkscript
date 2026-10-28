#!/usr/bin/env bash
# Claude Code hook: PreToolUse on Bash. Blocks commands that would change main or master:
# committing on them, pushing to them, force pushes anywhere, deleting them.
# Exit 2 blocks the command and feeds stderr back to Claude; exit 0 lets it run.
#
# This reads the command line, so it catches mistakes, not bypasses: an alias, a script,
# or `bash -c` gets through. The server-side branch ruleset is the gate.
#
# Adding a rule: write rule_<name> <dir> <subcommand> <args...> that returns 1 after
# printing why to stderr (via block), and add it to the chain in check_git.
set -euo pipefail

PROTECTED=(main master)

input="$(cat)"

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
print("" if value is None else value)
' "$1"
    fi
}

# Split a command line into words, honouring quotes and backslashes. Each run of
# ; & | or newline outside quotes becomes a single ";" word that ends a segment.
tokenize() {
    local line="$1" word="" quote="" have=0 c i
    words=()
    for ((i = 0; i < ${#line}; i++)); do
        c="${line:i:1}"
        if [[ "$quote" == "'" ]]; then
            if [[ "$c" == "'" ]]; then quote=""; else word+="$c"; fi
        elif [[ "$quote" == '"' ]]; then
            if [[ "$c" == '"' ]]; then
                quote=""
            elif [[ "$c" == "\\" && "${line:i+1:1}" == [\"\\\$\`] ]]; then
                word+="${line:i+1:1}"
                i=$((i + 1))
            else
                word+="$c"
            fi
        elif [[ "$c" == "'" || "$c" == '"' ]]; then
            quote="$c"
            have=1
        elif [[ "$c" == "\\" ]]; then
            word+="${line:i+1:1}"
            have=1
            i=$((i + 1))
        elif [[ "$c" == [[:space:]] && "$c" != $'\n' ]]; then
            ((have)) && words+=("$word")
            word="" have=0
        elif [[ "$c" == [\;\&\|$'\n'] ]]; then
            ((have)) && words+=("$word")
            word="" have=0
            # ${words[-1]} needs bash 4.3; macOS ships 3.2.
            [[ "${#words[@]}" -gt 0 && "${words[${#words[@]}-1]}" == ";" ]] || words+=(";")
        else
            word+="$c"
            have=1
        fi
    done
    ((have)) && words+=("$word")
    return 0
}

is_protected() {
    local name="${1#refs/heads/}" p
    for p in "${PROTECTED[@]}"; do
        [[ "$name" == "$p" ]] && return 0
    done
    return 1
}

current_branch() {
    git -C "$1" symbolic-ref --quiet --short HEAD 2>/dev/null || true
}

block() {
    printf 'guard-bash: blocked. %s\n' "$1" >&2
    return 1
}

rule_commit_on_protected() {
    local dir="$1" sub="$2" branch
    [[ "$sub" == commit ]] || return 0
    branch="$(current_branch "$dir")"
    is_protected "$branch" || return 0
    block "\`git commit\` on $branch. Create a feature branch first: git switch -c <branch>"
}

rule_force_push() {
    local sub="$2" arg
    [[ "$sub" == push ]] || return 0
    shift 2
    for arg in "$@"; do
        case "$arg" in
            --force | --force-with-lease | --force-with-lease=* | +*)
                block "force push (\`$arg\`). Push a new branch instead of rewriting a published one."
                return 1
                ;;
            --*) ;;
            -*f*)
                block "force push (\`$arg\`). Push a new branch instead of rewriting a published one."
                return 1
                ;;
        esac
    done
}

rule_push_to_protected() {
    local dir="$1" sub="$2" arg branch dst remote="" refspecs=() skip=0
    [[ "$sub" == push ]] || return 0
    shift 2
    branch="$(current_branch "$dir")"
    for arg in "$@"; do
        if ((skip)); then
            skip=0
            continue
        fi
        case "$arg" in
            --all | --mirror | --branches)
                block "\`git push $arg\` pushes every branch, including ${PROTECTED[*]}. Push one feature branch by name."
                return 1
                ;;
            -o | --push-option | --repo | --receive-pack | --exec) skip=1 ;;
            -*) ;;
            *) if [[ -z "$remote" ]]; then remote="$arg"; else refspecs+=("$arg"); fi ;;
        esac
    done
    if [[ "${#refspecs[@]}" -eq 0 ]]; then
        is_protected "$branch" || return 0
        block "\`git push\` from $branch pushes $branch. Commit on a feature branch and push that."
        return 1
    fi
    for arg in "${refspecs[@]}"; do
        arg="${arg#+}"
        dst="${arg##*:}"
        [[ "$dst" == HEAD ]] && dst="$branch"
        if is_protected "$dst"; then
            block "push to $dst (\`$arg\`). Push a feature branch and open a PR."
            return 1
        fi
    done
}

rule_delete_protected() {
    local sub="$2" arg deleting=0 targets=()
    [[ "$sub" == branch ]] || return 0
    shift 2
    for arg in "$@"; do
        case "$arg" in
            --delete) deleting=1 ;;
            --*) ;;
            -*[dD]*) deleting=1 ;;
            -*) ;;
            *) targets+=("$arg") ;;
        esac
    done
    ((deleting)) || return 0
    for arg in "${targets[@]}"; do
        if is_protected "$arg"; then
            block "deleting branch $arg."
            return 1
        fi
    done
}

# Run every rule against one `git ...` invocation. $1 is the directory it runs in.
check_git() {
    local dir="$1"
    shift
    # Global options come before the subcommand; -C changes the directory.
    while [[ $# -gt 0 && "$1" == -* ]]; do
        case "$1" in
            -C)
                [[ "${2:-}" == /* ]] && dir="$2" || dir="$dir/${2:-}"
                shift 2
                ;;
            -c | --git-dir | --work-tree | --namespace) shift 2 ;;
            *) shift ;;
        esac
    done
    [[ $# -gt 0 ]] || return 0
    rule_commit_on_protected "$dir" "$@" &&
        rule_force_push "$dir" "$@" &&
        rule_push_to_protected "$dir" "$@" &&
        rule_delete_protected "$dir" "$@"
}

command="$(json_field .tool_input.command)"
dir="$(json_field .cwd)"
dir="${dir:-${CLAUDE_PROJECT_DIR:-$PWD}}"
[[ -n "$command" ]] || exit 0

tokenize "$command"
words+=(";")
segment=()
for word in "${words[@]}"; do
    if [[ "$word" != ";" ]]; then
        segment+=("$word")
        continue
    fi
    # Drop leading VAR=value assignments.
    while [[ "${#segment[@]}" -gt 0 && "${segment[0]}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; do
        segment=("${segment[@]:1}")
    done
    if [[ "${#segment[@]}" -gt 0 ]]; then
        case "${segment[0]}" in
            cd)
                # Track `cd dir && git ...` so the branch is read where git runs.
                target="${segment[1]:-$HOME}"
                [[ "$target" == /* ]] && dir="$target" || dir="$dir/$target"
                ;;
            git | */git)
                check_git "$dir" "${segment[@]:1}" || exit 2
                ;;
        esac
    fi
    segment=()
done
exit 0
