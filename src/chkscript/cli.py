from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import NoReturn

from chkscript.analyzer import AnalysisError, ScriptTooLargeError, analyze
from chkscript.config import (
    DEFAULT_HOSTED_MODEL,
    DEFAULT_LOCAL_MODEL,
    ConfigError,
    load_config,
)
from chkscript.formatter import format_json, format_terminal

logger = logging.getLogger("chkscript")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chkscript",
        description="Analyze shell scripts for safety issues using Claude",
    )
    parser.add_argument(
        "file",
        nargs="?",
        metavar="FILE",
        help="Script file to analyze (reads from stdin if omitted)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed output including all code snippets",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "Model to use (default: $CHKSCRIPT_MODEL, else "
            f"{DEFAULT_HOSTED_MODEL} when ANTHROPIC_API_KEY is set, "
            f"else {DEFAULT_LOCAL_MODEL})"
        ),
    )
    return parser


def _read_script(file_arg: str | None) -> str:
    if file_arg:
        try:
            with open(file_arg, encoding="utf-8", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            _error(f"File not found: {file_arg}")
        except PermissionError:
            _error(f"Permission denied: {file_arg}")
        except OSError as e:
            _error(f"Cannot read file: {e}")

    if not sys.stdin.isatty():
        return sys.stdin.read()

    _error(
        "No input. Provide a file argument or pipe a script via stdin.\n"
        "Usage: chkscript script.sh\n"
        "       curl -fsSL https://example.com/install.sh | chkscript"
    )


def _configure_logging() -> None:
    # Fresh handler per run so it binds to the current sys.stderr.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)


def _error(msg: str) -> NoReturn:
    logger.error("Error: %s", msg)
    sys.exit(3)


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _configure_logging()

    try:
        settings = load_config(model=args.model)
    except ConfigError as e:
        _error(str(e))

    if not os.environ.get("ANTHROPIC_API_KEY"):
        _error(
            "ANTHROPIC_API_KEY not set.\n" "  export ANTHROPIC_API_KEY='your-key-here'"
        )

    script = _read_script(args.file)

    if not script.strip():
        _error("Empty script provided")

    try:
        result = analyze(script, model=settings.model)
    except ScriptTooLargeError as e:
        _error(str(e))
    except AnalysisError as e:
        _error(str(e))
    except KeyboardInterrupt:
        sys.exit(3)

    if args.json_output:
        print(format_json(result))
    else:
        print(format_terminal(result, verbose=args.verbose))

    sys.exit(result.max_severity.value)
