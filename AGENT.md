# Agent Guidelines

When modifying this project:

1. Run `uv run pytest` after changes to verify tests pass
2. Keep the single-dependency philosophy (only `anthropic` at runtime)
3. All errors should exit with code 3 and print to stderr
4. Findings severity: SAFE=0, WARNING=1, UNSAFE=2
5. The analyzer retries once on JSON parse failure from Claude
