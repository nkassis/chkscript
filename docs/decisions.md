# Decisions

One line per deviation from a global default or other design choice, newest last: `YYYY-MM-DD — what was chosen — why`.

- 2026-10-26 — Python 3.11 floor instead of the template's 3.13 — wider install base for a CLI; nothing needs newer.
- 2026-10-26 — stdlib `logging` instead of structlog — a CLI whose logs are never shipped or queried (the global default's own exit).
- 2026-10-26 — `argparse` instead of Click — single command, no extra dependency.
- 2026-10-26 — no mypy; type hints enforced by Ruff `ANN` — matches the stack's Black plus Ruff hook contract.
- 2026-10-26 — `stacks/shell` not applied — `tests/fixtures/` and `tests/examples/` are intentionally bad Bash and its hook would block edits there.
- 2026-10-26 — tests stay in `tests/` — existing layout, which the template allows.
- 2026-10-26 — when both `X_API_KEY` and `X_API_KEY_FILE` are set, `X_API_KEY` wins — matches "env already set wins"; the spec does not say.
- 2026-10-26 — `CHKSCRIPT_DEPTH` above 4 is rejected (exit 3), not clamped — the spec says "capped at 4"; an explicit error beats a silent change.
- 2026-10-26 — default models: `claude-sonnet-5-5` when `ANTHROPIC_API_KEY` is set, else `ollama:gpt-oss:20b` — v0.1's `claude-sonnet-4-20250514` is retired (404); chosen by the maintainer during NIM-71. The Ollama default is resolved now but only usable once phase 3 wires the provider.
- 2026-10-28 — shellcheck codes SC1090 and SC1091 suppressed — both report that shellcheck cannot follow a `source`d file, which describes the scanning environment, not the script.
- 2026-10-28 — Semgrep rules live in `src/chkscript/rules/` rather than a top-level `rules/` — CLAUDE.md layout; hatch ships it as package data with no build config change.
- 2026-10-28 — rule `persistence-append` also fires on any write (not only `>>`) into cron and systemd unit directories, and on `crontab FILE` / `| crontab -` — creating a unit or crontab entry is the persistence the spec's "appends to crontab or systemd units" means.
- 2026-10-28 — rule `insecure-permissions` fires on `chmod 777` and setuid/setgid anywhere; only `chown root` is limited to paths under `$HOME` or `/tmp` — the spec's sentence is ambiguous, and a world-writable or setuid file is dangerous wherever it is.
- 2026-10-28 — rule `unverified-download` ignores comment lines when looking for a verifier — otherwise a comment such as `# verified with sha256sum` lowers a deterministic finding (threat model property 1).
- 2026-10-28 — `k3d-with-checksum.sh` is `unsafe`, not `warning` as in the spec's fixture table — its `rm -rf "$K3D_TMP_ROOT"` matches `rm-rf-variable`, and the maintainer chose to keep the rule as specified; the spec table needs updating.
- 2026-10-28 — a Semgrep crash, timeout or non-parse error is treated like a parse failure (a `chkscript` warning, `semgrep-failure`, and the regex rules run) — the floor must not silently disappear when the tool misbehaves.
- 2026-10-28 — "golden suite under the regex fallback alone" means Semgrep replaced by regex with shellcheck still running — without shellcheck `warnings_only.sh` cannot be a warning, and the warning tier is independent of the unsafe-tier engine.
- 2026-10-28 — `stacks/shell` stays unapplied after the NIM-95 installer corpus, rather than installed with `check-shell.sh` excluding `tests/corpus/` — every `.sh` here is a fixture, a verbatim third-party installer, or a hook copied from claude-code-patterns and linted there; there is no first-party shell to protect, and the hook has no exclude, so the alternative means forking it. Revisit if first-party shell appears.
